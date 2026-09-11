package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/st3fan/full-reverse/ripestat"
)

const defaultDNSPort = "53"

// errNotFound indicates the name does not exist (NXDOMAIN).
var errNotFound = errors.New("no such host")

// Result is one JSONL record emitted per IP address.
type Result struct {
	IP    string   `json:"ip"`
	PTR   []string `json:"ptr"`
	Error string   `json:"error,omitempty"`
}

// dnsResolver wraps one or more upstream servers with a display name and
// per-resolver metrics. A resolver with multiple servers (the system
// configuration) tries them in order until one answers.
type dnsResolver struct {
	name    string
	servers []string
	udp     *dns.Client
	tcp     *dns.Client

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

// lookupPTR performs a single PTR lookup for ip, trying each configured server
// in order. It returns errNotFound when the name does not exist.
func (d *dnsResolver) lookupPTR(ctx context.Context, ip netip.Addr) ([]string, error) {
	reverse, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return nil, err
	}

	msg := new(dns.Msg)
	msg.SetQuestion(reverse, dns.TypePTR)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range d.servers {
		names, err := d.exchange(ctx, msg, server)
		if err == nil {
			return names, nil
		}
		if errors.Is(err, errNotFound) {
			return nil, errNotFound
		}
		lastErr = err
	}
	return nil, lastErr
}

// exchange sends msg to server over UDP, retrying over TCP if the response is
// truncated, and maps the response to PTR names.
func (d *dnsResolver) exchange(ctx context.Context, msg *dns.Msg, server string) ([]string, error) {
	resp, _, err := d.udp.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, fmt.Errorf("query %s on %s: %w", msg.Question[0].Name, server, err)
	}
	if resp.Truncated {
		resp, _, err = d.tcp.ExchangeContext(ctx, msg, server)
		if err != nil {
			return nil, fmt.Errorf("query %s on %s (tcp): %w", msg.Question[0].Name, server, err)
		}
	}

	switch resp.Rcode {
	case dns.RcodeSuccess:
		names := make([]string, 0, len(resp.Answer))
		for _, rr := range resp.Answer {
			if ptr, ok := rr.(*dns.PTR); ok {
				names = append(names, strings.TrimSuffix(ptr.Ptr, "."))
			}
		}
		return names, nil
	case dns.RcodeNameError:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("query %s on %s: %s", msg.Question[0].Name, server, dns.RcodeToString[resp.Rcode])
	}
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		dnsServers  stringList
		concurrency int
		retries     int
		timeout     time.Duration
	)

	flag.Var(&dnsServers, "d", "DNS server to use (e.g. 8.8.8.8:53); repeatable, defaults to system resolver")
	flag.IntVar(&concurrency, "c", 32, "number of concurrent reverse lookups")
	flag.IntVar(&retries, "r", 4, "retries for timeouts and I/O errors (NXDOMAIN is never retried)")
	flag.DurationVar(&timeout, "t", 2500*time.Millisecond, "per-attempt lookup timeout")
	flag.Parse()

	if concurrency < 1 {
		fmt.Fprintln(os.Stderr, "error: concurrency must be >= 1")
		os.Exit(2)
	}
	if retries < 0 {
		fmt.Fprintln(os.Stderr, "error: retry count must be >= 0")
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inputs, err := readInputs(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resolvers, err := buildResolvers(dnsServers, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Expand the mixed list of CIDRs and ASNs into IPv4 prefixes.
	prefixes, err := resolveTargets(ctx, inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	total := uint64(0)
	for _, p := range prefixes {
		total += uint64(1) << (32 - p.Bits())
	}
	logf("looking up %d IPs across %d CIDR(s)", total, len(prefixes))

	start := time.Now()
	var scanned, resolved, notFound, failed atomic.Uint64
	var rr atomic.Uint64

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, p := range prefixes {
		for addr := p.Masked().Addr(); p.Contains(addr); addr = addr.Next() {
			ip := addr
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				defer reportProgress(&scanned, &resolved, total, start)

				idx := rr.Add(1) - 1
				dr := resolvers[idx%uint64(len(resolvers))]

				names, err := lookupWithRetries(ctx, dr, ip, timeout, retries)
				if err != nil {
					// A missing PTR record is expected and not interesting; skip it.
					if errors.Is(err, errNotFound) {
						notFound.Add(1)
						return
					}
					failed.Add(1)
					emit(Result{IP: ip.String(), PTR: []string{}, Error: err.Error()})
					return
				}

				res := Result{IP: ip.String(), PTR: []string{}}
				// Trim trailing dots for cleaner output.
				for _, n := range names {
					res.PTR = append(res.PTR, strings.TrimSuffix(n, "."))
				}
				if len(res.PTR) > 0 {
					resolved.Add(1)
				} else {
					notFound.Add(1)
				}
				emit(res)
			}()
		}
	}

	wg.Wait()

	logf("done: %d IPs looked up, %d resolved, %d without PTR, %d failed in %s",
		total, resolved.Load(), notFound.Load(), failed.Load(),
		time.Since(start).Round(time.Millisecond))

	for _, dr := range resolvers {
		reqs := dr.requests.Load()
		var avg time.Duration
		if reqs > 0 {
			avg = time.Duration(dr.totalNs.Load() / int64(reqs))
		}
		logf("resolver %s: %d request(s), %d error(s), avg response %s",
			dr.name, reqs, dr.errors.Load(), avg.Round(time.Microsecond))
	}
}

// lookupWithRetries performs a reverse lookup for one IP, retrying timeouts
// and other non-NXDOMAIN errors up to retries times. Each attempt gets its own
// timeout. The returned error is the last one seen; NXDOMAIN is returned
// immediately without retrying. Per-attempt timing is recorded on dr.
func lookupWithRetries(ctx context.Context, dr *dnsResolver, ip netip.Addr, timeout time.Duration, retries int) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		lctx, cancel := context.WithTimeout(ctx, timeout)
		begin := time.Now()
		names, err := dr.lookupPTR(lctx, ip)
		cancel()
		dr.record(time.Since(begin), err != nil && !errors.Is(err, errNotFound))
		if err == nil {
			return names, nil
		}
		if errors.Is(err, errNotFound) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// outMu serializes writes to stdout and stderr so that concurrently emitted
// JSONL records and progress lines never interleave on the same file/pipe.
var outMu sync.Mutex

// emit writes one JSON record followed by a newline to stdout.
func emit(r Result) {
	b, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal: %v\n", err)
		return
	}
	b = append(b, '\n')

	outMu.Lock()
	os.Stdout.Write(b)
	outMu.Unlock()
}

// reportProgress increments the scanned counter and, for runs larger than a
// /24, logs an intermediate progress line every 256 completed lookups. The
// final batch is left to the end-of-run summary.
func reportProgress(scanned, resolved *atomic.Uint64, total uint64, start time.Time) {
	n := scanned.Add(1)
	if total <= 256 || n%256 != 0 || n == total {
		return
	}
	logf("progress: %d/%d IPs scanned (%.1f%%), %d resolved, %s elapsed",
		n, total, float64(n)/float64(total)*100, resolved.Load(),
		time.Since(start).Round(time.Millisecond))
}

// logf writes a timestamped progress line to stderr. The timestamp is RFC 3339
// (ISO 8601) in the system's local timezone.
func logf(format string, args ...any) {
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))

	outMu.Lock()
	os.Stderr.WriteString(line)
	outMu.Unlock()
}

// readInputs reads CIDRs and ASNs from the given arguments, or from stdin if
// none are provided. An argument that names an existing file is read as a list
// of targets; any other argument is treated as a literal CIDR or ASN. In
// files, multiple whitespace/comma separated values per line are accepted, and
// comments starting with '#' are ignored.
func readInputs(args []string) ([]string, error) {
	var inputs []string

	if len(args) == 0 {
		inputs, err := scanCIDRs(os.Stdin, inputs)
		if err != nil {
			return nil, err
		}
		if len(inputs) == 0 {
			return nil, fmt.Errorf("no CIDRs provided")
		}
		return inputs, nil
	}

	for _, arg := range args {
		f, err := os.Open(arg)
		if err != nil {
			// Not a readable file: treat the argument as a literal CIDR.
			inputs = append(inputs, arg)
			continue
		}
		inputs, err = scanCIDRs(f, inputs)
		f.Close()
		if err != nil {
			return nil, err
		}
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("no CIDRs provided")
	}
	return inputs, nil
}

// scanCIDRs appends CIDRs read from r to inputs.
func scanCIDRs(r io.Reader, inputs []string) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ReplaceAll(line, ",", " ")
		inputs = append(inputs, strings.Fields(line)...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return inputs, nil
}

// resolveTargets converts a mixed list of CIDRs and ASNs into IPv4 prefixes.
// ASNs ("AS15169", "as15169", or bare "15169") are expanded to their announced
// prefixes via the RIPE Stat API.
func resolveTargets(ctx context.Context, inputs []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	var asns []string

	for _, in := range inputs {
		if p, err := netip.ParsePrefix(in); err == nil {
			if !p.Addr().Is4() {
				return nil, fmt.Errorf("only IPv4 CIDRs are supported: %q", in)
			}
			prefixes = append(prefixes, p)
			continue
		}
		if _, err := ripestat.NormalizeASN(in); err == nil {
			asns = append(asns, in)
			continue
		}
		return nil, fmt.Errorf("invalid CIDR or ASN %q", in)
	}

	if len(asns) > 0 {
		client := ripestat.New()
		for _, asn := range asns {
			resource, err := ripestat.NormalizeASN(asn)
			if err != nil {
				return nil, err
			}
			announced, err := client.AnnouncedPrefixes(ctx, resource)
			if err != nil {
				return nil, err
			}
			list := make([]string, len(announced))
			for i, p := range announced {
				list[i] = p.String()
			}
			logf("%s: %d announced IPv4 prefix(es): %s", resource, len(announced), strings.Join(list, ", "))
			prefixes = append(prefixes, announced...)
		}
	}

	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no CIDRs or ASNs provided")
	}
	return prefixes, nil
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
		name:    name,
		servers: servers,
		udp:     &dns.Client{Net: "udp", Timeout: timeout, DialTimeout: timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout, DialTimeout: timeout},
	}
}
