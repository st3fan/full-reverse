package main

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/st3fan/full-reverse/ripestat"
)

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

// lookup returns the AS number and BGP prefix of the most specific known
// prefix containing addr, or 0/false when there is no match.
func (x *asnIndex) lookup(addr netip.Addr) (uint32, netip.Prefix, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	for bits := addr.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(addr, bits).Masked()
		if asn, ok := x.byNet[p]; ok {
			return asn, p, true
		}
	}
	return 0, netip.Prefix{}, false
}

// asnResolver determines the announcing AS (number, name, and organization) for
// an IP. It consults prefixes already known from the cache or AS targets before
// calling RIPE Stat, and records learned prefixes so later lookups are free.
type asnResolver struct {
	client  ripeClient
	index   *asnIndex
	mu      sync.Mutex // serializes API lookups and avoids duplicate work
	names   map[uint32]ripestat.ASInfo
	unknown map[netip.Prefix]struct{} // successful unknown-AS results, scoped to this run
	log     logFunc
}

// resolve returns the AS number, AS info, and BGP prefix for ip. The prefix is
// invalid when BGP/AS information is not available. All lookups are serialized,
// which also avoids duplicate API calls for the same prefix.
func (r *asnResolver) resolve(ctx context.Context, ip netip.Addr) (uint32, ripestat.ASInfo, netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return 0, ripestat.ASInfo{}, netip.Prefix{}
	}

	if asn, prefix, ok := r.index.lookup(ip); ok {
		return asn, r.nameLocked(ctx, asn), prefix
	}
	for bits := ip.BitLen(); bits >= 0; bits-- {
		if _, ok := r.unknown[netip.PrefixFrom(ip, bits).Masked()]; ok {
			return 0, ripestat.ASInfo{}, netip.Prefix{}
		}
	}

	overview, err := r.client.PrefixOverview(ctx, ip.String())
	if err != nil {
		r.log.printf("warning: AS lookup for %s failed: %v", ip, err)
		return 0, ripestat.ASInfo{}, netip.Prefix{}
	}
	if overview.Prefix.IsValid() {
		r.index.add(overview.Prefix, overview.ASN)
	}
	if overview.ASN == 0 {
		prefix := overview.Prefix
		if !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Contains(ip) {
			prefix = netip.PrefixFrom(ip, 32)
		}
		if r.unknown == nil {
			r.unknown = make(map[netip.Prefix]struct{})
		}
		r.unknown[prefix.Masked()] = struct{}{}
		return 0, ripestat.ASInfo{}, netip.Prefix{}
	}
	info := ripestat.ASInfo{Name: overview.ASName, Org: overview.ASOrg}
	if info.Name != "" || info.Org != "" {
		r.rememberLocked(overview.ASN, info)
	} else {
		info = r.nameLocked(ctx, overview.ASN)
	}
	return overview.ASN, info, overview.Prefix
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
		r.log.printf("warning: AS overview lookup for AS%d failed: %v", asn, err)
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
