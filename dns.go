package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// dnsResolver wraps one or more upstream servers with a display name and
// per-resolver metrics. A resolver with multiple servers (the system
// configuration) tries them in order until one answers.
type dnsResolver struct {
	name       string
	servers    []string
	tcp        *dns.Client
	tcpSlots   chan struct{}
	mu         sync.Mutex
	transports map[string]*udpTransport
	ports      *udpPortHistory
	closed     bool
	sendBudget func(context.Context) (*sendPermit, error)

	requests atomic.Uint64
	errors   atomic.Uint64
	totalNs  atomic.Int64
}

// record accounts for one lookup attempt against this resolver.
func (d *dnsResolver) record(elapsed time.Duration, failed bool) {
	d.requests.Add(1)
	d.totalNs.Add(int64(elapsed))
	if failed {
		d.errors.Add(1)
	}
}

// query performs a single DNS question, trying each configured server in
// order. It returns errNotFound when the name does not exist.
func (d *dnsResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return d.queryPermitted(ctx, name, qtype, false, nil)
}
func (d *dnsResolver) queryScheduled(ctx context.Context, name string, qtype uint16, permit *sendPermit) (*dns.Msg, error) {
	return d.queryPermitted(ctx, name, qtype, true, permit)
}
func (d *dnsResolver) queryPermitted(ctx context.Context, name string, qtype uint16, prepaid bool, permit *sendPermit) (*dns.Msg, error) {
	defer permit.finish(false)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for i, server := range d.servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := d.exchangePermitted(ctx, msg, server, prepaid && i == 0, permitForServer(permit, i))
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, errNotFound) {
			return nil, errNotFound
		}
		lastErr = err
	}
	return nil, lastErr
}

// exchange sends msg to server over UDP, retrying over TCP if the response is
// truncated, and maps the response code to an error.
func (d *dnsResolver) exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	return d.exchangePermitted(ctx, msg, server, false, nil)
}
func permitForServer(p *sendPermit, index int) *sendPermit {
	if index == 0 {
		return p
	}
	return nil
}
func (d *dnsResolver) exchangePermitted(ctx context.Context, msg *dns.Msg, server string, prepaid bool, permit *sendPermit) (*dns.Msg, error) {
	if !prepaid && d.sendBudget != nil {
		var err error
		permit, err = d.sendBudget(ctx)
		if err != nil {
			return nil, err
		}
	}
	defer permit.finish(false)
	transport, err := d.transport(server)
	if err != nil {
		return nil, err
	}
	var notify func()
	if permit != nil {
		notify = func() { permit.finish(true) }
	}
	resp, err := transport.exchangeNotified(ctx, msg, notify)
	// Release an unused initial grant before trying another system nameserver.
	permit.finish(false)
	if err != nil {
		return nil, fmt.Errorf("query %s on %s: %w", msg.Question[0].Name, server, err)
	}
	if resp.Truncated {
		select {
		case d.tcpSlots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp, _, err = exchangeContextBudget(ctx, d.tcp, msg, server, d.sendBudget)
		<-d.tcpSlots
		if err != nil {
			return nil, fmt.Errorf("query %s on %s (tcp): %w", msg.Question[0].Name, server, err)
		}
		if resp.Id != msg.Id || !validDNSReply(msg.Question[0], msg.Opcode, resp) || resp.Truncated {
			return nil, fmt.Errorf("query %s on %s (tcp): invalid or truncated DNS response", msg.Question[0].Name, server)
		}
	}

	switch resp.Rcode {
	case dns.RcodeSuccess:
		return resp, nil
	case dns.RcodeNameError:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("query %s on %s: %s", msg.Question[0].Name, server, dns.RcodeToString[resp.Rcode])
	}
}

func (d *dnsResolver) transport(server string) (*udpTransport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if d.transports == nil {
		d.transports = make(map[string]*udpTransport)
	}
	if d.transports[server] == nil {
		if d.ports == nil {
			d.ports = &udpPortHistory{}
		}
		d.transports[server] = newUDPTransportWithPorts(server, d.ports)
	}
	return d.transports[server], nil
}

func (d *dnsResolver) close() {
	d.mu.Lock()
	d.closed = true
	transports := make([]*udpTransport, 0, len(d.transports))
	for _, transport := range d.transports {
		transports = append(transports, transport)
	}
	d.mu.Unlock()
	for _, transport := range transports {
		transport.close()
	}
}

// exchangeContext retains per-exchange connections and closes pending reads on cancellation.
func exchangeContext(ctx context.Context, client *dns.Client, msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	return exchangeContextBudget(ctx, client, msg, server, nil)
}
func exchangeContextBudget(ctx context.Context, client *dns.Client, msg *dns.Msg, server string, budget func(context.Context) (*sendPermit, error)) (*dns.Msg, time.Duration, error) {
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		return nil, 0, err
	}
	if budget != nil {
		conn.Conn = &pacedTCPConn{Conn: conn.Conn, ctx: ctx, budget: budget}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	response, elapsed, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if ctx.Err() != nil {
		return nil, elapsed, ctx.Err()
	}
	return response, elapsed, err
}

// ptrNames extracts PTR targets from a response, without trailing dots.
func ptrNames(resp *dns.Msg) []string {
	names := make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			names = append(names, strings.TrimSuffix(ptr.Ptr, "."))
		}
	}
	return names
}

// aRecords extracts IPv4 addresses from a response.
func aRecords(resp *dns.Msg) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(a.A); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs
}

// One TCP message consumes one permit, including when the write fails. Waiting
// happens after dialing so connection setup never holds the global send grant.
type pacedTCPConn struct {
	net.Conn
	ctx     context.Context
	budget  func(context.Context) (*sendPermit, error)
	started bool
}

func (c *pacedTCPConn) Write(data []byte) (int, error) {
	if c.started {
		return c.Conn.Write(data)
	}
	c.started = true
	permit, err := c.budget(c.ctx)
	if err != nil {
		return 0, err
	}
	defer permit.finish(false)
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(data)
	permit.finish(true)
	return n, err
}

// buildResolvers builds one dnsResolver per -d value, or a single resolver
// backed by the system nameservers when none were given.
func buildResolvers(addrs []string, timeout time.Duration) ([]*dnsResolver, error) {
	if len(addrs) == 0 {
		servers, err := systemServers()
		if err != nil {
			return nil, err
		}
		return []*dnsResolver{newDNSResolver("system", servers, timeout)}, nil
	}

	resolvers := make([]*dnsResolver, 0, len(addrs))
	for _, a := range addrs {
		addr := a
		// Accept both "host" and "host:port" forms.
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, defaultDNSPort)
		}
		resolvers = append(resolvers, newDNSResolver(addr, []string{addr}, timeout))
	}
	return resolvers, nil
}

// systemServers returns the nameservers from /etc/resolv.conf as host:port.
func systemServers() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}
	servers := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		servers = append(servers, net.JoinHostPort(s, cfg.Port))
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no nameservers found in /etc/resolv.conf")
	}
	return servers, nil
}

func newDNSResolver(name string, servers []string, timeout time.Duration) *dnsResolver {
	return &dnsResolver{
		name:     name,
		servers:  servers,
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout, DialTimeout: timeout},
		tcpSlots: make(chan struct{}, maxPendingDNS),
	}
}
