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
	closed     bool

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
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range d.servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := d.exchange(ctx, msg, server)
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
	transport, err := d.transport(server)
	if err != nil {
		return nil, err
	}
	resp, err := transport.exchange(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("query %s on %s: %w", msg.Question[0].Name, server, err)
	}
	if resp.Truncated {
		select {
		case d.tcpSlots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp, _, err = exchangeContext(ctx, d.tcp, msg, server)
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
		d.transports[server] = newUDPTransport(server)
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
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		return nil, 0, err
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

// lookupWithRetries performs a DNS query, retrying timeouts and other
// non-NXDOMAIN errors up to retries times. Each attempt gets its own timeout.
// The returned error is the last one seen; NXDOMAIN is returned immediately
// without retrying. Per-attempt timing is recorded on dr.
func lookupWithRetries(ctx context.Context, dr *dnsResolver, name string, qtype uint16, timeout time.Duration, retries int) (*dns.Msg, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		begin := time.Now()
		resp, err := dr.query(lctx, name, qtype)
		cancel()
		dr.record(time.Since(begin), err != nil && !errors.Is(err, errNotFound))
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, errNotFound) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// forwardConfirms reports whether name resolves (A) to ip.
func forwardConfirms(ctx context.Context, dr *dnsResolver, name string, ip netip.Addr, timeout time.Duration, retries int) bool {
	resp, err := lookupWithRetries(ctx, dr, name, dns.TypeA, timeout, retries)
	if err != nil {
		return false
	}
	for _, a := range aRecords(resp) {
		if a == ip {
			return true
		}
	}
	return false
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
