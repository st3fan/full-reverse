package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

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
	rate, resolverRate                    int
	timeout                               time.Duration
	lookupAS, forwardConfirmedOnly, quiet bool
}

func runLookups(parent context.Context, opts lookupOptions, inputs []string, stdout, stderr io.Writer, services cliServices) (runErr error) {
	if opts.concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1")
	}
	if opts.retries < 0 {
		return fmt.Errorf("retry count must be >= 0")
	}
	if err := validateRates(opts.rate, opts.resolverRate); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	out := newRunOutput(ctx, stdout, stderr, opts.quiet, cancel)
	defer func() {
		if err := out.finish(); err != nil {
			runErr = err
		}
	}()
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
	// Different configured names (or repeated -d flags) can reach the same
	// endpoint. Retire source ports across the whole run, not just one alias.
	ports := &udpPortHistory{}
	for _, resolver := range resolvers {
		resolver.mu.Lock()
		resolver.ports = ports
		resolver.mu.Unlock()
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
	progress := &lookupProgress{out: out, total: total, start: start}
	scheduler, err := newTaskScheduler(schedulerConfig{concurrency: opts.concurrency, resolvers: len(resolvers), rate: opts.rate, resolverRate: opts.resolverRate})
	if err != nil {
		return err
	}
	for i, dr := range resolvers {
		if scheduler.enabled() {
			dr.sendBudget = func(ctx context.Context) (*sendPermit, error) { return scheduler.wait(ctx, i) }
		}
	}
	scheduleErr := runLookupPipeline(ctx, scheduler, targets, resolvers, opts, asnRes, progress)
	// Flush all accepted JSONL before declaring the run complete. A final write
	// failure takes precedence over cancellation or a successful DNS schedule.
	out.finish()

	if err := out.failure(); err != nil {
		return err
	}
	if scheduleErr != nil {
		return scheduleErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	out.logf("done: %d IPs looked up, %d resolved, %d without PTR, %d unconfirmed, %d failed in %s",
		total, progress.resolved.Load(), progress.notFound.Load(), progress.unconfirmed.Load(), progress.failed.Load(),
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
