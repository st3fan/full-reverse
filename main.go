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
	IP     string   `json:"ip"`
	Prefix string   `json:"prefix"`
	ASN    *uint32  `json:"asn"`
	ASName *string  `json:"as_name"`
	ASOrg  *string  `json:"as_org"`
	PTR    []string `json:"ptr"`
	Error  string   `json:"error,omitempty"`
}

// target is one prefix to scan together with where it came from.
type target struct {
	prefix netip.Prefix
	asn    uint32 // announcing AS number, 0 for explicitly provided CIDRs
	asName string // announcing AS name, empty when unknown
	asOrg  string // announcing AS organization, empty when unknown
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

// asnIndex maps known prefixes to their announcing ASN. It is safe for
// concurrent use. Lookups walk from the most specific to the least specific
// supernet, so a /0 entry matches every address.
type asnIndex struct {
	mu    sync.RWMutex
	byNet map[netip.Prefix]uint32
}

func newASNIndex() *asnIndex {
	return &asnIndex{byNet: make(map[netip.Prefix]uint32)}
}

func (x *asnIndex) add(p netip.Prefix, asn uint32) {
	if asn == 0 || !p.IsValid() {
		return
	}
	p = p.Masked()
	x.mu.Lock()
	if _, ok := x.byNet[p]; !ok {
		x.byNet[p] = asn
	}
	x.mu.Unlock()
}

// lookup returns the AS number of the most specific known prefix containing
// addr, or 0 when there is no match.
func (x *asnIndex) lookup(addr netip.Addr) (uint32, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	for bits := addr.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(addr, bits).Masked()
		if asn, ok := x.byNet[p]; ok {
			return asn, true
		}
	}
	return 0, false
}

// asnResolver determines the announcing AS (number, name, and organization) for
// an IP. It consults prefixes already known from the cache or AS targets before
// calling RIPE Stat, and records learned prefixes so later lookups are free.
type asnResolver struct {
	client *ripestat.Client
	index  *asnIndex
	mu     sync.Mutex // serializes API lookups and avoids duplicate work
	names  map[uint32]ripestat.ASInfo
}

// resolve returns the AS number and info for ip, or 0/zero when unknown. All
// lookups are serialized, which also avoids duplicate API calls for the same
// prefix.
func (r *asnResolver) resolve(ctx context.Context, ip netip.Addr) (uint32, ripestat.ASInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	asn, _ := r.index.lookup(ip)
	if asn == 0 {
		overview, err := r.client.PrefixOverview(ctx, ip.String())
		if err != nil {
			logf("warning: AS lookup for %s failed: %v", ip, err)
			return 0, ripestat.ASInfo{}
		}
		asn = overview.ASN
		if overview.Prefix.IsValid() {
			r.index.add(overview.Prefix, overview.ASN)
		}
		if asn != 0 && (overview.ASName != "" || overview.ASOrg != "") {
			info := ripestat.ASInfo{Name: overview.ASName, Org: overview.ASOrg}
			r.rememberLocked(asn, info)
			return asn, info
		}
	}
	if asn == 0 {
		return 0, ripestat.ASInfo{}
	}
	return asn, r.nameLocked(ctx, asn)
}

// nameLocked returns the AS info for asn, consulting the in-memory map and then
// the as-overview API (which is itself cached on disk). The caller must hold
// r.mu.
func (r *asnResolver) nameLocked(ctx context.Context, asn uint32) ripestat.ASInfo {
	if info, ok := r.names[asn]; ok {
		return info
	}
	info, err := r.client.ASOverview(ctx, fmt.Sprintf("AS%d", asn))
	if err != nil {
		logf("warning: AS overview lookup for AS%d failed: %v", asn, err)
		return ripestat.ASInfo{}
	}
	r.rememberLocked(asn, info)
	return info
}

// rememberLocked records AS info. The caller must hold r.mu.
func (r *asnResolver) rememberLocked(asn uint32, info ripestat.ASInfo) {
	if r.names == nil {
		r.names = make(map[uint32]ripestat.ASInfo)
	}
	r.names[asn] = info
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
		lookupAS             bool
		concurrency          int
		retries              int
		timeout              time.Duration
	)

	flag.Var(&dnsServers, "d", "DNS server to use (e.g. 8.8.8.8:53); repeatable, defaults to system resolver")
	flag.Var(&inputFiles, "i", "read targets from a file, one per line; use - for stdin")
	flag.Var(&inputFiles, "input", "read targets from a file, one per line; use - for stdin")
	flag.BoolVar(&quiet, "q", false, "silence progress and summary logging")
	flag.BoolVar(&quiet, "quiet", false, "silence progress and summary logging")
	flag.BoolVar(&lookupAS, "a", false, "look up the announcing ASN for IPs whose ASN is not already known")
	flag.BoolVar(&lookupAS, "lookup-as", false, "look up the announcing ASN for IPs whose ASN is not already known")
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

	// Expand the mixed list of CIDRs, IPs, and ASNs into scan targets.
	client := ripestat.New()
	client.Logf = logf
	targets, err := resolveTargets(ctx, client, inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// When requested, prepare IP -> ASN resolution. Cached announced-prefixes
	// responses are loaded first so known prefixes never hit the API.
	var asnRes *asnResolver
	if lookupAS {
		index := newASNIndex()
		cached := client.CachedPrefixASNs()
		for p, asn := range cached {
			index.add(p, asn)
		}
		for _, t := range targets {
			if t.asn != 0 {
				index.add(t.prefix, t.asn)
			}
		}
		asnRes = &asnResolver{client: client, index: index}
		logf("loaded %d cached prefix(es) for AS resolution", len(cached))
	}

	total := uint64(0)
	for _, t := range targets {
		total += uint64(1) << (32 - t.prefix.Bits())
	}
	logf("looking up %d IPs across %d CIDR(s)", total, len(targets))

	start := time.Now()
	var scanned, resolved, notFound, unconfirmed, failed atomic.Uint64
	var rr atomic.Uint64

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		for addr := t.prefix.Masked().Addr(); t.prefix.Contains(addr); addr = addr.Next() {
			ip := addr
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				defer reportProgress(&scanned, &resolved, total, start)

				res := Result{IP: ip.String(), Prefix: t.prefix.String(), PTR: []string{}}

				if t.asn != 0 {
					asn := t.asn
					res.ASN = &asn
					if t.asName != "" {
						name := t.asName
						res.ASName = &name
					}
					if t.asOrg != "" {
						org := t.asOrg
						res.ASOrg = &org
					}
				} else if asnRes != nil {
					// A lookup that yields nothing leaves the fields nil, i.e. null.
					asn, info := asnRes.resolve(ctx, ip)
					if asn != 0 {
						res.ASN = &asn
					}
					if info.Name != "" {
						name := info.Name
						res.ASName = &name
					}
					if info.Org != "" {
						org := info.Org
						res.ASOrg = &org
					}
				}

				idx := rr.Add(1) - 1
				dr := resolvers[idx%uint64(len(resolvers))]

				reverse, err := dns.ReverseAddr(ip.String())
				if err != nil {
					res.Error = err.Error()
					failed.Add(1)
					emit(res)
					return
				}

				resp, err := lookupWithRetries(ctx, dr, reverse, dns.TypePTR, timeout, retries)
				if err != nil {
					// A missing PTR record is expected and not interesting; skip it.
					if errors.Is(err, errNotFound) {
						notFound.Add(1)
						return
					}
					res.Error = err.Error()
					failed.Add(1)
					emit(res)
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
				res.PTR = names
				resolved.Add(1)
				emit(res)
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

// quiet suppresses progress and summary logging when set via -q/-quiet.
var quiet bool

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
// (ISO 8601) in the system's local timezone. When quiet is set, nothing is
// written.
func logf(format string, args ...any) {
	if quiet {
		return
	}
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))

	outMu.Lock()
	os.Stderr.WriteString(line)
	outMu.Unlock()
}

// readInputs collects targets from explicit input files, positional arguments,
// and (when nothing else is given) stdin. Values in input files and stdin are
// one target (CIDR, plain IP, ASN, or AS name) per line, though whitespace/comma
// separated values and '#' comments are also accepted. A positional argument
// that names an existing file is read as a list of targets; any other
// positional argument is treated as a literal CIDR, IP, or ASN. An input file
// of "-" reads stdin.
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
			// Not a readable file: treat the argument as a literal CIDR, IP, or ASN.
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
		return nil, fmt.Errorf("no CIDRs, IPs, or ASNs provided")
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

// pickASN chooses a single ASN from RIPE Stat search matches, preferring an
// exact as-name match and rejecting ambiguous names.
func pickASN(name string, matches []ripestat.ASMatch) (ripestat.ASMatch, error) {
	var exact []ripestat.ASMatch
	for _, m := range matches {
		if strings.EqualFold(m.Name, name) {
			exact = append(exact, m)
		}
	}

	switch {
	case len(exact) == 1:
		return exact[0], nil
	case len(matches) == 1:
		return matches[0], nil
	default:
		if len(exact) > 1 {
			matches = exact
		}
		labels := make([]string, len(matches))
		for i, m := range matches {
			labels[i] = fmt.Sprintf("AS%d (%s)", m.ASN, m.Name)
		}
		return ripestat.ASMatch{}, fmt.Errorf("ambiguous AS name %q matches %s; use an AS number", name, strings.Join(labels, ", "))
	}
}

// resolveTargets converts a mixed list of CIDRs, plain IPs, ASNs, and AS names
// into scan targets. A plain IP is treated as a /32. ASNs ("AS15169",
// "as15169", or bare "15169") are expanded to their announced prefixes via the
// RIPE Stat API, and each such target records the ASN it came from. An AS name
// such as "AMAZON-AES" is resolved to an ASN first, and is rejected when it
// matches more than one AS.
func resolveTargets(ctx context.Context, client *ripestat.Client, inputs []string) ([]target, error) {
	var targets []target
	var asns []string

	for _, in := range inputs {
		if p, err := netip.ParsePrefix(in); err == nil {
			if !p.Addr().Is4() {
				return nil, fmt.Errorf("only IPv4 CIDRs are supported: %q", in)
			}
			targets = append(targets, target{prefix: p.Masked()})
			continue
		}
		if a, err := netip.ParseAddr(in); err == nil {
			a = a.Unmap()
			if !a.Is4() {
				return nil, fmt.Errorf("only IPv4 addresses are supported: %q", in)
			}
			targets = append(targets, target{prefix: netip.PrefixFrom(a, 32)})
			continue
		}
		if _, err := ripestat.NormalizeASN(in); err == nil {
			asns = append(asns, in)
			continue
		}

		// Otherwise treat the token as an AS name (e.g. AMAZON-AES).
		matches, err := client.SearchASNs(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("resolving AS name %q: %w", in, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("invalid CIDR, IP, ASN, or AS name %q", in)
		}
		match, err := pickASN(in, matches)
		if err != nil {
			return nil, err
		}
		logf("%s resolved to AS%d (%s)", in, match.ASN, match.Description)
		asns = append(asns, fmt.Sprintf("AS%d", match.ASN))
	}

	if len(asns) > 0 {
		for _, asn := range asns {
			resource, err := ripestat.NormalizeASN(asn)
			if err != nil {
				return nil, err
			}
			number, err := ripestat.ASNNumber(resource)
			if err != nil {
				return nil, err
			}
			info, err := client.ASOverview(ctx, resource)
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
			for _, p := range announced {
				targets = append(targets, target{prefix: p, asn: number, asName: info.Name, asOrg: info.Org})
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no CIDRs, IPs, or ASNs provided")
	}
	return targets, nil
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
