package main

import (
	"context"
	"sync"
)

const metadataWorkers = 4

func metadataWindow(concurrency int) int { return max(64, 2*concurrency) }

func runLookupPipeline(parent context.Context, scheduler *taskScheduler, targets []target, resolvers []*dnsResolver, opts lookupOptions, asn *asnResolver, progress *lookupProgress) error {
	iterator := targetIterator{targets: targets}
	sequence := 0
	next := func() *lookupJob {
		ip, target, ok := iterator.next()
		if !ok {
			return nil
		}
		index := sequence % len(resolvers)
		sequence++
		return newLookupJob(ip, target, index, resolvers[index], opts, progress)
	}
	if asn == nil {
		_, err := scheduler.run(parent, func() *scheduledTask {
			job := next()
			if job == nil {
				return nil
			}
			return &job.task
		})
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	window := make(chan struct{}, metadataWindow(opts.concurrency))
	dnsJobs := make(chan *scheduledTask, 2*opts.concurrency)
	metadata := make(chan *lookupJob, cap(window))
	var workers sync.WaitGroup
	// Each job is released only when both DNS and metadata have completed. Output
	// happens after their writes synchronize through joinMu. The finite window
	// applies backpressure without retaining the entire scan in either queue.
	arrive := func(job *lookupJob) {
		job.joinMu.Lock()
		job.pending--
		done := job.pending == 0
		job.joinMu.Unlock()
		if done {
			if ctx.Err() == nil {
				job.finalize()
			}
			<-window
		}
	}
	for range metadataWorkers {
		workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-metadata:
					if !ok {
						return
					}
					job.applyMetadata(asn.resolveMetadata(ctx, job.ip))
					arrive(job)
				}
			}
		})
	}
	workers.Go(func() {
		defer close(dnsJobs)
		defer close(metadata)
		for {
			select {
			case window <- struct{}{}:
			case <-ctx.Done():
				return
			}
			if ctx.Err() != nil {
				return
			}
			job := next()
			if job == nil {
				<-window
				return
			}
			job.completed, job.pending = arrive, 1
			if job.result.ASN == nil {
				if cached, ready := asn.cached(job.ip); ready {
					job.applyMetadata(cached)
				} else {
					job.pending = 2
					// The queue is as large as the shared admission window, so publishing
					// metadata never prevents this admitted job's DNS task from being sent.
					metadata <- job
				}
			}
			select {
			case dnsJobs <- &job.task:
			case <-ctx.Done():
				return
			}
		}
	})
	_, err := scheduler.runQueued(ctx, dnsJobs)
	if err != nil {
		cancel()
	}
	workers.Wait()
	return err
}
