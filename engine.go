package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/st3fan/full-reverse/ripestat"
)

type ripeClient interface {
	AnnouncedPrefixes(context.Context, string) ([]netip.Prefix, error)
	ASOverview(context.Context, string) (ripestat.ASInfo, error)
	PrefixOverview(context.Context, string) (*ripestat.PrefixOverview, error)
	SearchASNs(context.Context, string) ([]ripestat.ASMatch, error)
	CachedPrefixASNs() map[netip.Prefix]uint32
}

// cliServices permits local DNS/HTTP fixtures without changing production policy.
// Services belong to one run; resolver counters and RIPE logging are run-scoped.
type cliServices struct {
	ripe      ripeClient
	resolvers func([]string, time.Duration) ([]*dnsResolver, error)
}

type lookupOptions struct {
	dnsServers                            []string
	concurrency, retries                  int
	timeout                               time.Duration
	lookupAS, forwardConfirmedOnly, quiet bool
}

func runLookups(parent context.Context, opts lookupOptions, inputs []string, stdout, stderr io.Writer, services cliServices) error {
	if opts.concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1")
	}
	if opts.retries < 0 {
		return fmt.Errorf("retry count must be >= 0")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	out := &runOutput{stdout: stdout, stderr: stderr, quiet: opts.quiet, cancel: cancel}
	if services.resolvers == nil {
		services.resolvers = buildResolvers
	}
	resolvers, err := services.resolvers(opts.dnsServers, opts.timeout)
	if err != nil {
		return err
	}
	if len(resolvers) == 0 {
		return fmt.Errorf("no DNS resolvers configured")
	}
	defer func() {
		for _, resolver := range resolvers {
			resolver.close()
		}
	}()

	// Expand the mixed list of CIDRs, IPs, and ASNs into scan targets.
	client := services.ripe
	if client == nil {
		c := ripestat.New()
		c.Logf = out.logf
		client = c
	}
	targets, err := resolveTargets(ctx, client, inputs, out.logf)
	if err != nil {
		if outputErr := out.failure(); outputErr != nil {
			return outputErr
		}
		return err
	}

	// When requested, prepare IP -> ASN resolution. Cached announced-prefixes
	// responses are loaded first so known prefixes never hit the API.
	var asnRes *asnResolver
	if opts.lookupAS {
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
		asnRes = &asnResolver{client: client, index: index, log: out.logf}
		out.logf("loaded %d cached prefix(es) for AS resolution", len(cached))
	}

	total := uint64(0)
	for _, t := range targets {
		total += uint64(1) << (32 - t.prefix.Bits())
	}
	out.logf("looking up %d IPs across %d CIDR(s)", total, len(targets))

	start := time.Now()
	var scanned, resolved, notFound, unconfirmed, failed atomic.Uint64
	var rr atomic.Uint64

	sem := make(chan struct{}, opts.concurrency)
	var wg sync.WaitGroup

scan:
	for _, t := range targets {
		for addr := t.prefix.Masked().Addr(); t.prefix.Contains(addr); addr = addr.Next() {
			ip := addr
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break scan
			}
			if ctx.Err() != nil {
				<-sem
				break scan
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				defer out.reportProgress(&scanned, &resolved, total, start)

				res := Result{IP: ip.String(), Target: t.label, PTR: []string{}}

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
					// The announced prefix is known from the AS expansion.
					prefix := t.prefix.String()
					res.Prefix = &prefix
				} else if asnRes != nil {
					// A lookup that yields nothing leaves the fields nil, i.e. null.
					asn, info, prefix := asnRes.resolve(ctx, ip)
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
					if prefix.IsValid() {
						p := prefix.String()
						res.Prefix = &p
					}
				}

				if ctx.Err() != nil {
					return
				}
				idx := rr.Add(1) - 1
				dr := resolvers[idx%uint64(len(resolvers))]

				reverse, err := dns.ReverseAddr(ip.String())
				if err != nil {
					res.Error = err.Error()
					failed.Add(1)
					out.emit(res)
					return
				}

				resp, err := lookupWithRetries(ctx, dr, reverse, dns.TypePTR, opts.timeout, opts.retries)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					// A missing PTR record is expected and not interesting; skip it.
					if errors.Is(err, errNotFound) {
						notFound.Add(1)
						return
					}
					res.Error = err.Error()
					failed.Add(1)
					out.emit(res)
					return
				}

				names := ptrNames(resp)

				// Forward confirmation: keep only names whose A record maps back
				// to the queried IP.
				if opts.forwardConfirmedOnly {
					confirmed := names[:0]
					for _, name := range names {
						if forwardConfirms(ctx, dr, name, ip, opts.timeout, opts.retries) {
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
				out.emit(res)
			}()
		}
	}

	wg.Wait()
	if err := out.failure(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	out.logf("done: %d IPs looked up, %d resolved, %d without PTR, %d unconfirmed, %d failed in %s",
		total, resolved.Load(), notFound.Load(), unconfirmed.Load(), failed.Load(),
		time.Since(start).Round(time.Millisecond))

	for _, dr := range resolvers {
		reqs := dr.requests.Load()
		var avg time.Duration
		if reqs > 0 {
			avg = time.Duration(dr.totalNs.Load() / int64(reqs))
		}
		out.logf("resolver %s: %d request(s), %d error(s), avg response %s",
			dr.name, reqs, dr.errors.Load(), avg.Round(time.Microsecond))
	}
	if err := out.failure(); err != nil {
		return err
	}
	return ctx.Err()
}

const defaultDNSPort = "53"

// errNotFound indicates the name does not exist (NXDOMAIN).
var errNotFound = errors.New("no such host")

// Result is one JSONL record emitted per IP address.
type Result struct {
	IP     string   `json:"ip"`
	Target string   `json:"target"`
	Prefix *string  `json:"prefix"`
	ASN    *uint32  `json:"asn"`
	ASName *string  `json:"as_name"`
	ASOrg  *string  `json:"as_org"`
	PTR    []string `json:"ptr"`
	Error  string   `json:"error,omitempty"`
}

// target is one prefix to scan together with where it came from.
type target struct {
	label  string // target as given by the user (CIDR, IP, ASN, or AS name)
	prefix netip.Prefix
	asn    uint32 // announcing AS number, 0 for explicitly provided CIDRs
	asName string // announcing AS name, empty when unknown
	asOrg  string // announcing AS organization, empty when unknown
}
