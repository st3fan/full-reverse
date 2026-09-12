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

// query performs a single DNS question, trying each configured server in
// order. It returns errNotFound when the name does not exist.
func (d *dnsResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range d.servers {
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
		return resp, nil
	case dns.RcodeNameError:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("query %s on %s: %s", msg.Question[0].Name, server, dns.RcodeToString[resp.Rcode])
	}
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

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		dnsServers           stringList
		inputFiles           stringList
		forwardConfirmedOnly bool
		concurrency          int
		retries              int
		timeout              time.Duration
	)

	flag.Var(&dnsServers, "d", "DNS server to use (e.g. 8.8.8.8:53); repeatable, defaults to system resolver")
	flag.Var(&inputFiles, "i", "read prefixes/ASNs from a file, one per line; use - for stdin")
	flag.Var(&inputFiles, "input", "read prefixes/ASNs from a file, one per line; use - for stdin")
	flag.BoolVar(&forwardConfirmedOnly, "forward-confirmed-only", false, "only report PTR records whose name resolves back to the same IP")
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

	inputs, err := readInputs(flag.Args(), inputFiles)
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
	var scanned, resolved, notFound, unconfirmed, failed atomic.Uint64
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

				reverse, err := dns.ReverseAddr(ip.String())
				if err != nil {
					failed.Add(1)
					emit(Result{IP: ip.String(), PTR: []string{}, Error: err.Error()})
					return
				}

				resp, err := lookupWithRetries(ctx, dr, reverse, dns.TypePTR, timeout, retries)
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

				names := ptrNames(resp)

				// Forward confirmation: keep only names whose A record maps back
				// to the queried IP.
				if forwardConfirmedOnly {
					confirmed := names[:0]
					for _, name := range names {
						if forwardConfirms(ctx, dr, name, ip, timeout, retries) {
							confirmed = append(confirmed, name)
						}
					}
					names = confirmed
					if len(names) == 0 {
						unconfirmed.Add(1)
						return
					}
				}

				if len(names) == 0 {
					notFound.Add(1)
					return
				}
				resolved.Add(1)
				emit(Result{IP: ip.String(), PTR: names})
			}()
		}
	}

	wg.Wait()

	logf("done: %d IPs looked up, %d resolved, %d without PTR, %d unconfirmed, %d failed in %s",
		total, resolved.Load(), notFound.Load(), unconfirmed.Load(), failed.Load(),
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

// lookupWithRetries performs a DNS query, retrying timeouts and other
// non-NXDOMAIN errors up to retries times. Each attempt gets its own timeout.
// The returned error is the last one seen; NXDOMAIN is returned immediately
// without retrying. Per-attempt timing is recorded on dr.
func lookupWithRetries(ctx context.Context, dr *dnsResolver, name string, qtype uint16, timeout time.Duration, retries int) (*dns.Msg, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
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

// readInputs collects targets from explicit input files, positional arguments,
// and (when nothing else is given) stdin. Values in input files and stdin are
// one CIDR or ASN per line, though whitespace/comma separated values and '#'
// comments are also accepted. A positional argument that names an existing
// file is read as a list of targets; any other positional argument is treated
// as a literal CIDR or ASN. An input file of "-" reads stdin.
func readInputs(args, inputFiles []string) ([]string, error) {
	var inputs []string

	for _, path := range inputFiles {
		if path == "-" {
			var err error
			inputs, err = scanCIDRs(os.Stdin, inputs)
			if err != nil {
				return nil, err
			}
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening input file %q: %w", path, err)
		}
		inputs, err = scanCIDRs(f, inputs)
		f.Close()
		if err != nil {
			return nil, err
		}
	}

	for _, arg := range args {
		if arg == "-" {
			var err error
			inputs, err = scanCIDRs(os.Stdin, inputs)
			if err != nil {
				return nil, err
			}
			continue
		}
		f, err := os.Open(arg)
		if err != nil {
			// Not a readable file: treat the argument as a literal CIDR or ASN.
			inputs = append(inputs, arg)
			continue
		}
		inputs, err = scanCIDRs(f, inputs)
		f.Close()
		if err != nil {
			return nil, err
		}
	}

	// With no explicit sources, read the target list from stdin.
	if len(args) == 0 && len(inputFiles) == 0 {
		var err error
		inputs, err = scanCIDRs(os.Stdin, inputs)
		if err != nil {
			return nil, err
		}
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("no CIDRs or ASNs provided")
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
