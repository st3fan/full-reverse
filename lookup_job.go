package main

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Only the scheduler advances this iterator. It retains one address, including
// across the final IPv4 address, rather than materializing a prefix.
type targetIterator struct {
	targets []target
	index   int
	address netip.Addr
}

func (it *targetIterator) next() (netip.Addr, target, bool) {
	if it.index == len(it.targets) {
		return netip.Addr{}, target{}, false
	}
	t := it.targets[it.index]
	if !it.address.IsValid() {
		it.address = t.prefix.Masked().Addr()
	}
	address := it.address
	it.address = address.Next()
	if !t.prefix.Contains(it.address) {
		it.index++
		it.address = netip.Addr{}
	}
	return address, t, true
}

type lookupProgress struct {
	out                                              *runOutput
	total                                            uint64
	start                                            time.Time
	scanned, resolved, notFound, unconfirmed, failed atomic.Uint64
}
type lookupJob struct {
	ip               netip.Addr
	result           Result
	resolver         *dnsResolver
	opts             lookupOptions
	progress         *lookupProgress
	task             scheduledTask
	name             string
	qtype            uint16
	attempt          int
	names, confirmed []string
	nameIndex        int
}

func newLookupJob(ip netip.Addr, t target, index int, dr *dnsResolver, opts lookupOptions, asn *asnResolver, progress *lookupProgress) *scheduledTask {
	reverse, _ := dns.ReverseAddr(ip.String()) // Iterator addresses are always IPv4.
	j := &lookupJob{ip: ip, result: Result{IP: ip.String(), Target: t.label, PTR: []string{}}, resolver: dr, opts: opts, progress: progress, name: reverse, qtype: dns.TypePTR}
	j.task = scheduledTask{resolver: index, paced: true, run: j.run}
	if t.asn != 0 {
		number, prefix := t.asn, t.prefix.String()
		j.result.ASN, j.result.Prefix = &number, &prefix
		if t.asName != "" {
			name := t.asName
			j.result.ASName = &name
		}
		if t.asOrg != "" {
			org := t.asOrg
			j.result.ASOrg = &org
		}
	} else if asn != nil {
		j.task.paced = false
		j.task.run = func(ctx context.Context, _ *sendPermit) taskCompletion {
			number, info, prefix := asn.resolve(ctx, ip)
			if ctx.Err() != nil {
				return taskCompletion{}
			}
			if number != 0 {
				j.result.ASN = &number
			}
			if info.Name != "" {
				j.result.ASName = &info.Name
			}
			if info.Org != "" {
				j.result.ASOrg = &info.Org
			}
			if prefix.IsValid() {
				text := prefix.String()
				j.result.Prefix = &text
			}
			j.task.paced, j.task.run = true, j.run
			return taskCompletion{next: &j.task}
		}
	}
	return &j.task
}
func (j *lookupJob) finish() taskCompletion {
	j.progress.out.reportProgress(&j.progress.scanned, &j.progress.resolved, j.progress.total, j.progress.start)
	return taskCompletion{}
}
func (j *lookupJob) emit() taskCompletion {
	j.result.PTR = j.confirmed
	j.progress.resolved.Add(1)
	j.progress.out.emit(j.result)
	return j.finish()
}
func (j *lookupJob) run(ctx context.Context, permit *sendPermit) taskCompletion {
	if ctx.Err() != nil {
		return taskCompletion{}
	}
	attemptCtx, cancel := context.WithTimeout(ctx, j.opts.timeout)
	begin := time.Now()
	response, err := j.resolver.queryScheduled(attemptCtx, j.name, j.qtype, permit)
	cancel()
	j.resolver.record(time.Since(begin), err != nil && !errors.Is(err, errNotFound))
	if ctx.Err() != nil {
		return taskCompletion{}
	}
	if err != nil && !errors.Is(err, errNotFound) && j.attempt < j.opts.retries {
		j.attempt++
		return taskCompletion{next: &j.task, retry: true}
	}
	j.attempt = 0
	if j.qtype == dns.TypePTR {
		if err != nil {
			if errors.Is(err, errNotFound) {
				j.progress.notFound.Add(1)
			} else {
				j.result.Error = err.Error()
				j.progress.failed.Add(1)
				j.progress.out.emit(j.result)
			}
			return j.finish()
		}
		j.names = ptrNames(response)
		if !j.opts.forwardConfirmedOnly {
			if len(j.names) == 0 {
				j.progress.notFound.Add(1)
				return j.finish()
			}
			j.confirmed = j.names
			return j.emit()
		}
		j.qtype = dns.TypeA
	} else {
		if err == nil {
			for _, address := range aRecords(response) {
				if address == j.ip {
					j.confirmed = append(j.confirmed, j.names[j.nameIndex])
					break
				}
			}
		}
		j.nameIndex++
	}
	if j.nameIndex < len(j.names) {
		j.name = j.names[j.nameIndex]
		return taskCompletion{next: &j.task}
	}
	if len(j.confirmed) == 0 {
		j.progress.unconfirmed.Add(1)
		return j.finish()
	}
	return j.emit()
}
