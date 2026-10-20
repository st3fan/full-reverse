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

// Metadata caches are protected only while reading or publishing data. HTTP
// calls never hold mu. Prefix discovery stays single-file so waiting addresses
// can reuse a newly reported covering prefix without guessing its boundaries.
type asnMetadata struct {
	asn    uint32
	info   ripestat.ASInfo
	prefix netip.Prefix
}
type asnFlight[T any] struct {
	done  chan struct{}
	value T
}
type asnResolver struct {
	client               ripeClient
	index                *asnIndex
	mu                   sync.Mutex
	names                map[uint32]ripestat.ASInfo
	unknown              map[netip.Prefix]struct{}
	prefixes             map[netip.Addr]*asnFlight[asnMetadata]
	nameFlights          map[uint32]*asnFlight[ripestat.ASInfo]
	once                 sync.Once
	prefixSlot, nameSlot chan struct{}
	log                  logFunc
}

func (r *asnResolver) init() {
	r.once.Do(func() {
		r.prefixSlot, r.nameSlot = make(chan struct{}, 1), make(chan struct{}, 1)
		r.prefixes = make(map[netip.Addr]*asnFlight[asnMetadata])
		r.nameFlights = make(map[uint32]*asnFlight[ripestat.ASInfo])
	})
}

// cached never waits for HTTP, even when an unrelated resource is in flight.
// A positive prefix without cached AS info still requires name enrichment.
func (r *asnResolver) cached(ip netip.Addr) (asnMetadata, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if asn, prefix, ok := r.index.lookup(ip); ok {
		info, ready := r.names[asn]
		return asnMetadata{asn, info, prefix}, ready
	}
	for bits := ip.BitLen(); bits >= 0; bits-- {
		if _, ok := r.unknown[netip.PrefixFrom(ip, bits).Masked()]; ok {
			return asnMetadata{}, true
		}
	}
	return asnMetadata{}, false
}
func (r *asnResolver) resolve(ctx context.Context, ip netip.Addr) (uint32, ripestat.ASInfo, netip.Prefix) {
	metadata := r.resolveMetadata(ctx, ip)
	return metadata.asn, metadata.info, metadata.prefix
}
func (r *asnResolver) resolveMetadata(ctx context.Context, ip netip.Addr) asnMetadata {
	if ctx.Err() != nil {
		return asnMetadata{}
	}
	if metadata, ready := r.cached(ip); ready {
		return metadata
	}
	if asn, prefix, ok := r.index.lookup(ip); ok {
		return asnMetadata{asn, r.name(ctx, asn), prefix}
	}
	r.init()
	r.mu.Lock()
	if flight := r.prefixes[ip]; flight != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return asnMetadata{}
		case <-flight.done:
			return flight.value
		}
	}
	flight := &asnFlight[asnMetadata]{done: make(chan struct{})}
	r.prefixes[ip] = flight
	r.mu.Unlock()
	value := r.discover(ctx, ip)
	r.mu.Lock()
	flight.value = value
	delete(r.prefixes, ip)
	close(flight.done)
	r.mu.Unlock()
	return value
}
func (r *asnResolver) discover(ctx context.Context, ip netip.Addr) asnMetadata {
	select {
	case r.prefixSlot <- struct{}{}:
	case <-ctx.Done():
		return asnMetadata{}
	}
	// Recheck after waiting: the previous request may have learned this prefix.
	metadata, ready := r.cached(ip)
	if ready {
		<-r.prefixSlot
		return metadata
	}
	if asn, prefix, ok := r.index.lookup(ip); ok {
		<-r.prefixSlot
		return asnMetadata{asn, r.name(ctx, asn), prefix}
	}
	overview, err := r.client.PrefixOverview(ctx, ip.String())
	if err != nil {
		<-r.prefixSlot
		r.log.printf("warning: AS lookup for %s failed: %v", ip, err)
		return asnMetadata{}
	}
	r.mu.Lock()
	r.index.add(overview.Prefix, overview.ASN)
	if overview.ASN == 0 {
		prefix := overview.Prefix
		if !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Contains(ip) {
			prefix = netip.PrefixFrom(ip, 32)
		}
		if r.unknown == nil {
			r.unknown = make(map[netip.Prefix]struct{})
		}
		r.unknown[prefix.Masked()] = struct{}{}
	} else if overview.ASName != "" || overview.ASOrg != "" {
		r.rememberLocked(overview.ASN, ripestat.ASInfo{Name: overview.ASName, Org: overview.ASOrg})
	}
	r.mu.Unlock()
	<-r.prefixSlot
	if overview.ASN == 0 {
		return asnMetadata{}
	}
	return asnMetadata{overview.ASN, r.name(ctx, overview.ASN), overview.Prefix}
}

// name coalesces requests by ASN. Its independent single-request lane permits
// AS names and prefix discovery to progress together, with at most two RIPE
// requests in flight. Failures are shared with waiters but are never cached.
func (r *asnResolver) name(ctx context.Context, asn uint32) ripestat.ASInfo {
	if ctx.Err() != nil {
		return ripestat.ASInfo{}
	}
	r.init()
	r.mu.Lock()
	if info, ok := r.names[asn]; ok {
		r.mu.Unlock()
		return info
	}
	if flight := r.nameFlights[asn]; flight != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ripestat.ASInfo{}
		case <-flight.done:
			return flight.value
		}
	}
	flight := &asnFlight[ripestat.ASInfo]{done: make(chan struct{})}
	r.nameFlights[asn] = flight
	r.mu.Unlock()
	info := r.fetchName(ctx, asn)
	r.mu.Lock()
	flight.value = info
	delete(r.nameFlights, asn)
	close(flight.done)
	r.mu.Unlock()
	return info
}
func (r *asnResolver) fetchName(ctx context.Context, asn uint32) ripestat.ASInfo {
	select {
	case r.nameSlot <- struct{}{}:
	case <-ctx.Done():
		return ripestat.ASInfo{}
	}
	defer func() { <-r.nameSlot }()
	r.mu.Lock()
	info, ok := r.names[asn]
	r.mu.Unlock()
	if ok {
		return info
	}
	info, err := r.client.ASOverview(ctx, fmt.Sprintf("AS%d", asn))
	if err != nil {
		r.log.printf("warning: AS overview lookup for AS%d failed: %v", asn, err)
		return ripestat.ASInfo{}
	}
	r.mu.Lock()
	// Prefer holder information learned from a simultaneous prefix response.
	if cached, ok := r.names[asn]; ok {
		info = cached
	} else {
		r.rememberLocked(asn, info)
	}
	r.mu.Unlock()
	return info
}
func (r *asnResolver) rememberLocked(asn uint32, info ripestat.ASInfo) {
	if r.names == nil {
		r.names = make(map[uint32]ripestat.ASInfo)
	}
	r.names[asn] = info
}
