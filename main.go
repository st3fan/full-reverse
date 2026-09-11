package main

import (
	"bufio"
	"context"
	"encoding/json"
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
)

// Result is one JSONL record emitted per IP address.
type Result struct {
	IP    string   `json:"ip"`
	PTR   []string `json:"ptr"`
	Error string   `json:"error,omitempty"`
}

// dnsResolver wraps a resolver with a display name and per-resolver metrics.
type dnsResolver struct {
	name      string // label for log output
	errServer string // server reported in DNSError messages; empty for system
	r         *net.Resolver

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

	inputs, err := readInputs(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resolvers := buildResolvers(dnsServers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse all CIDRs up front.
	prefixes, err := parseCIDRs(inputs)
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
					if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
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
		names, err := dr.r.LookupAddr(lctx, ip.String())
		cancel()
		if err == nil {
			dr.record(time.Since(begin), false)
			return names, nil
		}
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			// NXDOMAIN is a valid response, not a resolver error.
			dr.record(time.Since(begin), false)
			return nil, err
		}
		dr.record(time.Since(begin), true)
		lastErr = err
	}

	// Go reports the resolv.conf server in DNSErrors even when a custom Dial
	// is used; correct it to the server we queried.
	if dnsErr, ok := lastErr.(*net.DNSError); ok && dr.errServer != "" {
		dnsErr.Server = dr.errServer
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

// readInputs reads CIDRs from the given arguments, or from stdin if none are
// provided. An argument that names an existing file is read as a list of
// CIDRs; any other argument is treated as a literal CIDR. In files, multiple
// whitespace/comma separated values per line are accepted, and comments
// starting with '#' are ignored.
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

func parseCIDRs(inputs []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, in := range inputs {
		p, err := netip.ParsePrefix(in)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", in, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("only IPv4 CIDRs are supported: %q", in)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// buildResolvers builds one dnsResolver per -d value, or a single resolver
// backed by the system configuration when none were given.
func buildResolvers(addrs []string) []*dnsResolver {
	if len(addrs) == 0 {
		return []*dnsResolver{{name: "system", r: net.DefaultResolver}}
	}

	resolvers := make([]*dnsResolver, 0, len(addrs))
	for _, a := range addrs {
		addr := a
		// Accept both "host" and "host:port" forms.
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, addr)
			},
		}
		resolvers = append(resolvers, &dnsResolver{name: addr, errServer: addr, r: resolver})
	}
	return resolvers
}
