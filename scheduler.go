package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// A task is one preparation step or one DNS attempt, never an entire retry
// loop. A continuation retains its address admission slot but releases its
// active-work slot. The source is advanced only while admission space exists.
type scheduledTask struct {
	resolver int
	paced    bool
	run      func(context.Context, *sendPermit) taskCompletion
}

type taskCompletion struct {
	next  *scheduledTask
	retry bool
	err   error
}

// finish is called at the actual write boundary, not after a DNS reply.
// False releases an unused permit without consuming rate credit.
type sendPermit struct {
	once     sync.Once
	complete func(bool)
}

func (p *sendPermit) finish(sent bool) {
	if p != nil {
		p.once.Do(func() { p.complete(sent) })
	}
}

type schedulerTimer interface {
	C() <-chan time.Time
	Reset(time.Duration)
	Stop()
}

type schedulerClock interface {
	Now() time.Time
	Timer(time.Duration) schedulerTimer
}

type realSchedulerClock struct{}

func (realSchedulerClock) Now() time.Time { return time.Now() }
func (realSchedulerClock) Timer(d time.Duration) schedulerTimer {
	return realSchedulerTimer{time.NewTimer(d)}
}

type realSchedulerTimer struct{ *time.Timer }

func (t realSchedulerTimer) C() <-chan time.Time   { return t.Timer.C }
func (t realSchedulerTimer) Reset(d time.Duration) { t.Timer.Reset(d) }
func (t realSchedulerTimer) Stop()                 { t.Timer.Stop() }

type schedulerConfig struct {
	concurrency, resolvers, rate, resolverRate int
	clock                                      schedulerClock
	onSend                                     func(int, time.Time) // optional observation, without retaining a trace
}

func validateRates(rate, resolverRate int) error {
	if rate < 0 || rate > int(time.Second) {
		return fmt.Errorf("rate must be between 0 and 1000000000 queries/second")
	}
	if resolverRate < 0 || resolverRate > int(time.Second) {
		return fmt.Errorf("resolver-rate must be between 0 and 1000000000 queries/second")
	}
	return nil
}

type schedulerStats struct{ admitted, peakTracked, peakActive int }

type fifo[T any] struct {
	items []T
	head  int
}

func (q *fifo[T]) len() int { return len(q.items) - q.head }
func (q *fifo[T]) peek() T  { return q.items[q.head] }
func (q *fifo[T]) push(v T) { q.items = append(q.items, v) }
func (q *fifo[T]) pop() T {
	v := q.items[q.head]
	var zero T
	q.items[q.head] = zero
	q.head++
	if q.head == len(q.items) {
		q.items = q.items[:0]
		q.head = 0
	} else if q.head >= 64 && q.head >= len(q.items)/2 {
		n := copy(q.items, q.items[q.head:])
		clear(q.items[n:])
		q.items = q.items[:n]
		q.head = 0
	}
	return v
}

type permitRequest struct {
	ctx      context.Context
	resolver int
	reply    chan *sendPermit
	mu       sync.Mutex
	canceled bool
	permit   *sendPermit
}

type sendAck struct {
	resolver int
	at       time.Time
	sent     bool
}
type resolverQueue struct {
	normal, retries        fifo[*scheduledTask]
	aux                    fifo[*permitRequest]
	preferRetry, preferAux bool
	next                   time.Time
	busy                   bool
}

type taskScheduler struct {
	config                           schedulerConfig
	clock                            schedulerClock
	requests                         chan *permitRequest
	acks                             chan sendAck
	ctx                              context.Context
	queues                           []resolverQueue
	nextGlobal                       time.Time
	globalBusy                       bool
	pendingPermits                   int
	globalInterval, resolverInterval time.Duration
}

func newTaskScheduler(config schedulerConfig) (*taskScheduler, error) {
	if config.concurrency < 1 || config.concurrency > int(^uint(0)>>1)/2 {
		return nil, fmt.Errorf("invalid scheduler concurrency")
	}
	if config.resolvers < 1 {
		return nil, fmt.Errorf("no scheduler resolvers")
	}
	if err := validateRates(config.rate, config.resolverRate); err != nil {
		return nil, err
	}
	clock := config.clock
	if clock == nil {
		clock = realSchedulerClock{}
	}
	s := &taskScheduler{config: config, clock: clock, requests: make(chan *permitRequest, config.concurrency),
		acks: make(chan sendAck, config.concurrency), queues: make([]resolverQueue, config.resolvers)}
	if config.rate > 0 {
		s.globalInterval = time.Second / time.Duration(config.rate)
	}
	if config.resolverRate > 0 {
		s.resolverInterval = time.Second / time.Duration(config.resolverRate)
	}
	return s, nil
}

func (s *taskScheduler) enabled() bool { return s.globalInterval > 0 || s.resolverInterval > 0 }

// wait is used for subsequent wire sends inside an active attempt: system
// nameserver fallback and TCP fallback. Initial sends are granted by run before
// starting an attempt deadline or consuming an active-work slot.
func (s *taskScheduler) wait(ctx context.Context, resolver int) (*sendPermit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.enabled() {
		return nil, nil
	}
	r := &permitRequest{ctx: ctx, resolver: resolver, reply: make(chan *sendPermit, 1)}
	select {
	case s.requests <- r:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case p := <-r.reply:
		if err := ctx.Err(); err != nil {
			p.finish(false)
			return nil, err
		}
		return p, nil
	case <-ctx.Done():
		r.mu.Lock()
		r.canceled = true
		p := r.permit
		r.mu.Unlock()
		p.finish(false)
		return nil, ctx.Err()
	}
}

func (s *taskScheduler) ready(resolver int, now time.Time) (time.Time, bool) {
	q := &s.queues[resolver]
	if s.globalBusy || q.busy {
		return time.Time{}, false
	}
	at := now
	if s.nextGlobal.After(at) {
		at = s.nextGlobal
	}
	if q.next.After(at) {
		at = q.next
	}
	return at, true
}

func (s *taskScheduler) permit(resolver int) *sendPermit {
	if !s.enabled() {
		return nil
	}
	s.pendingPermits++
	if s.globalInterval > 0 {
		s.globalBusy = true
	}
	if s.resolverInterval > 0 {
		s.queues[resolver].busy = true
	}
	return &sendPermit{complete: func(sent bool) {
		ack := sendAck{resolver: resolver, at: s.clock.Now(), sent: sent}
		select {
		case s.acks <- ack:
		case <-s.ctx.Done():
		}
	}}
}

func (s *taskScheduler) acknowledge(ack sendAck) {
	s.pendingPermits--
	q := &s.queues[ack.resolver]
	s.globalBusy = false
	q.busy = false
	if ack.sent {
		if s.globalInterval > 0 {
			s.nextGlobal = ack.at.Add(s.globalInterval)
		}
		if s.resolverInterval > 0 {
			q.next = ack.at.Add(s.resolverInterval)
		}
		if s.config.onSend != nil {
			s.config.onSend(ack.resolver, ack.at)
		}
	}
}

func (q *resolverQueue) cleanAux() {
	n := q.aux.len()
	for range n {
		r := q.aux.pop()
		if r.ctx.Err() == nil {
			q.aux.push(r)
		}
	}
}

func (q *resolverQueue) task(canSend bool) (*scheduledTask, bool) {
	normal := q.normal.len() > 0 && (!q.normal.peek().paced || canSend)
	retry := q.retries.len() > 0 && (!q.retries.peek().paced || canSend)
	if retry && (!normal || q.preferRetry) {
		return q.retries.peek(), true
	}
	if normal {
		return q.normal.peek(), false
	}
	return nil, false
}

func (s *taskScheduler) run(parent context.Context, source func() *scheduledTask) (schedulerStats, error) {
	return s.runSource(parent, source, nil)
}

// runQueued accepts asynchronously produced work without blocking the actor's
// receiver, pacing acknowledgements, or attempt completions during admission.
func (s *taskScheduler) runQueued(parent context.Context, source <-chan *scheduledTask) (schedulerStats, error) {
	return s.runSource(parent, nil, source)
}
func (s *taskScheduler) runSource(parent context.Context, source func() *scheduledTask, queued <-chan *scheduledTask) (schedulerStats, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	s.ctx = ctx
	var stats schedulerStats
	active, tracked, cursor := 0, 0, 0
	sourceDone := false
	completed := make(chan taskCompletion, s.config.concurrency)
	timer := s.clock.Timer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	stop := func(err error) (schedulerStats, error) {
		cancel()
		// Every worker respects ctx. Completion capacity equals the active bound;
		// no canceled worker is left blocked on a result or a pacing request.
		for active > 0 {
			<-completed
			active--
		}
		return stats, err
	}
	admit := func(task *scheduledTask) error {
		if task == nil || task.resolver < 0 || task.resolver >= len(s.queues) {
			return fmt.Errorf("invalid task resolver")
		}
		s.queues[task.resolver].normal.push(task)
		tracked++
		stats.admitted++
		stats.peakTracked = max(stats.peakTracked, tracked)
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return stop(err)
		}
		for source != nil && !sourceDone && tracked < 2*s.config.concurrency {
			if ctx.Err() != nil {
				break
			}
			task := source()
			if task == nil {
				sourceDone = true
				break
			}
			if err := admit(task); err != nil {
				return stop(err)
			}
		}
		if sourceDone && tracked == 0 && s.pendingPermits == 0 {
			return stats, nil
		}
		now := s.clock.Now()
		var wake time.Time
		dispatched := false
		for offset := range len(s.queues) {
			index := (cursor + offset) % len(s.queues)
			q := &s.queues[index]
			q.cleanAux()
			at, available := s.ready(index, now)
			canSend := available && !at.After(now)
			var task *scheduledTask
			var retry bool
			if active < s.config.concurrency {
				task, retry = q.task(canSend)
			}
			aux := q.aux.len() > 0 && canSend
			if aux && (task == nil || q.preferAux) {
				r := q.aux.pop()
				r.mu.Lock()
				if !r.canceled && r.ctx.Err() == nil {
					p := s.permit(index)
					r.permit = p
					r.reply <- p
				}
				r.mu.Unlock()
				q.preferAux = false
				cursor = (index + 1) % len(s.queues)
				dispatched = true
				break
			}
			if task != nil {
				contended := q.normal.len() > 0 && q.retries.len() > 0
				if retry {
					q.retries.pop()
				} else {
					q.normal.pop()
				}
				if contended {
					q.preferRetry = !retry
				}
				q.preferAux = true
				var permit *sendPermit
				if task.paced {
					permit = s.permit(index)
				}
				active++
				stats.peakActive = max(stats.peakActive, active)
				go func(task *scheduledTask, p *sendPermit) {
					result := func() taskCompletion { defer p.finish(false); return task.run(ctx, p) }()
					completed <- result
				}(task, permit)
				cursor = (index + 1) % len(s.queues)
				dispatched = true
				break
			}
			waiting := q.aux.len() > 0 || (active < s.config.concurrency && (q.normal.len() > 0 || q.retries.len() > 0))
			if waiting && available && at.After(now) && (wake.IsZero() || at.Before(wake)) {
				wake = at
			}
		}
		if dispatched {
			continue
		}
		var tick <-chan time.Time
		timer.Stop()
		if !wake.IsZero() {
			timer.Reset(wake.Sub(s.clock.Now()))
			tick = timer.C()
		}
		var input <-chan *scheduledTask
		if !sourceDone && tracked < 2*s.config.concurrency {
			input = queued
		}
		select {
		case task, ok := <-input:
			if !ok {
				sourceDone = true
			} else if err := admit(task); err != nil {
				return stop(err)
			}
		case <-ctx.Done():
			return stop(ctx.Err())
		case result := <-completed:
			active--
			if result.err != nil {
				return stop(result.err)
			}
			if result.next == nil {
				tracked--
			} else {
				task := result.next
				if task.resolver < 0 || task.resolver >= len(s.queues) {
					return stop(fmt.Errorf("invalid continuation resolver"))
				}
				q := &s.queues[task.resolver]
				if result.retry {
					q.retries.push(task)
				} else {
					q.normal.push(task)
				}
			}
		case request := <-s.requests:
			if request.resolver < 0 || request.resolver >= len(s.queues) {
				return stop(fmt.Errorf("invalid permit resolver"))
			}
			if request.ctx.Err() == nil {
				s.queues[request.resolver].aux.push(request)
			}
		case ack := <-s.acks:
			s.acknowledge(ack)
		case <-tick:
		}
	}
}
