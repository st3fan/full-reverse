package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSchedulerClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeSchedulerTimer
	armed  chan time.Time
}
type fakeSchedulerTimer struct {
	clock   *fakeSchedulerClock
	channel chan time.Time
	due     time.Time
	active  bool
}

func newFakeSchedulerClock() *fakeSchedulerClock {
	return &fakeSchedulerClock{now: time.Unix(1000, 0), armed: make(chan time.Time, 64)}
}
func (c *fakeSchedulerClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeSchedulerClock) Timer(d time.Duration) schedulerTimer {
	t := &fakeSchedulerTimer{clock: c, channel: make(chan time.Time, 1)}
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	t.Reset(d)
	return t
}
func (c *fakeSchedulerClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if t.active && !t.due.After(c.now) {
			t.active = false
			t.channel <- c.now
		}
	}
}
func (t *fakeSchedulerTimer) C() <-chan time.Time { return t.channel }
func (t *fakeSchedulerTimer) Stop()               { t.clock.mu.Lock(); t.active = false; t.clock.mu.Unlock() }
func (t *fakeSchedulerTimer) Reset(d time.Duration) {
	c := t.clock
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-t.channel:
	default:
	}
	t.due = c.now.Add(d)
	t.active = true
	if d <= 0 {
		t.active = false
		t.channel <- c.now
	}
	select {
	case c.armed <- t.due:
	default:
	}
}
func (c *fakeSchedulerClock) awaitArm(t *testing.T, due time.Time) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case at := <-c.armed:
			if at.Equal(due) {
				return
			}
		case <-timer.C:
			t.Fatalf("scheduler did not arm %v", due)
		}
	}
}

type schedulerResult struct {
	stats schedulerStats
	err   error
}

func startScheduler(s *taskScheduler, ctx context.Context, source func() *scheduledTask) <-chan schedulerResult {
	done := make(chan schedulerResult, 1)
	go func() { stats, err := s.run(ctx, source); done <- schedulerResult{stats, err} }()
	return done
}
func awaitScheduler(t *testing.T, done <-chan schedulerResult) schedulerResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop")
		return schedulerResult{}
	}
}
func mustScheduler(t *testing.T, c schedulerConfig) *taskScheduler {
	t.Helper()
	s, err := newTaskScheduler(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func taskSource(tasks ...*scheduledTask) func() *scheduledTask {
	index := 0
	return func() *scheduledTask {
		if index == len(tasks) {
			return nil
		}
		task := tasks[index]
		index++
		return task
	}
}

func TestSchedulerInterleavesFreshWorkAndRetries(t *testing.T) {
	s := mustScheduler(t, schedulerConfig{concurrency: 1, resolvers: 1})
	var order []int
	attempt := 0
	var retry *scheduledTask
	retry = &scheduledTask{paced: true, run: func(context.Context, *sendPermit) taskCompletion {
		order = append(order, 0)
		attempt++
		if attempt < 3 {
			return taskCompletion{next: retry, retry: true}
		}
		return taskCompletion{}
	}}
	fresh := func(id int) *scheduledTask {
		return &scheduledTask{paced: true, run: func(context.Context, *sendPermit) taskCompletion { order = append(order, id); return taskCompletion{} }}
	}
	stats, err := s.run(context.Background(), taskSource(retry, fresh(1), fresh(2)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []int{0, 1, 0, 2, 0}) {
		t.Fatalf("dispatch order %v", order)
	}
	if stats.peakActive != 1 || stats.peakTracked != 2 || stats.admitted != 3 {
		t.Fatalf("bounds %+v", stats)
	}
}

func TestSchedulerBoundedAdmissionAndCancellation(t *testing.T) {
	s := mustScheduler(t, schedulerConfig{concurrency: 3, resolvers: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var admitted atomic.Int64
	started := make(chan struct{}, 3)
	done := startScheduler(s, ctx, func() *scheduledTask {
		admitted.Add(1)
		return &scheduledTask{run: func(ctx context.Context, _ *sendPermit) taskCompletion {
			started <- struct{}{}
			<-ctx.Done()
			return taskCompletion{}
		}}
	})
	for range 3 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("worker not started")
		}
	}
	if admitted.Load() != 6 {
		t.Fatalf("read %d inputs, want bounded window 6", admitted.Load())
	}
	cancel()
	r := awaitScheduler(t, done)
	if !errors.Is(r.err, context.Canceled) || r.stats.peakActive != 3 || r.stats.peakTracked != 6 {
		t.Fatalf("cancel/bounds %+v", r)
	}
}

func TestSchedulerNoCatchupBurst(t *testing.T) {
	clock := newFakeSchedulerClock()
	base := clock.Now()
	sent := make(chan time.Time, 3)
	s := mustScheduler(t, schedulerConfig{concurrency: 3, resolvers: 1, rate: 10, clock: clock, onSend: func(_ int, at time.Time) { sent <- at }})
	task := func() *scheduledTask {
		return &scheduledTask{paced: true, run: func(_ context.Context, p *sendPermit) taskCompletion { p.finish(true); return taskCompletion{} }}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startScheduler(s, ctx, taskSource(task(), task(), task()))
	read := func() time.Time {
		select {
		case at := <-sent:
			return at
		case <-time.After(2 * time.Second):
			t.Fatal("missing send")
			return time.Time{}
		}
	}
	if at := read(); !at.Equal(base) {
		t.Fatal(at)
	}
	clock.awaitArm(t, base.Add(100*time.Millisecond))
	clock.advance(10 * time.Second)
	if at := read(); !at.Equal(base.Add(10 * time.Second)) {
		t.Fatal(at)
	}
	clock.awaitArm(t, base.Add(10100*time.Millisecond))
	select {
	case at := <-sent:
		t.Fatalf("catch-up burst at %v", at)
	default:
	}
	clock.advance(100 * time.Millisecond)
	if at := read(); !at.Equal(base.Add(10100 * time.Millisecond)) {
		t.Fatal(at)
	}
	if r := awaitScheduler(t, done); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestSchedulerSlowResolverDoesNotBlockAnother(t *testing.T) {
	clock := newFakeSchedulerClock()
	base := clock.Now()
	type observation struct {
		resolver int
		at       time.Time
	}
	sent := make(chan observation, 8)
	s := mustScheduler(t, schedulerConfig{concurrency: 2, resolvers: 2, resolverRate: 1, clock: clock, onSend: func(r int, at time.Time) { sent <- observation{r, at} }})
	release := make(chan struct{})
	held := &scheduledTask{resolver: 0, paced: true, run: func(ctx context.Context, p *sendPermit) taskCompletion {
		select {
		case <-release:
			p.finish(true)
		case <-ctx.Done():
		}
		return taskCompletion{}
	}}
	fast := func() *scheduledTask {
		return &scheduledTask{resolver: 1, paced: true, run: func(_ context.Context, p *sendPermit) taskCompletion { p.finish(true); return taskCompletion{} }}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startScheduler(s, ctx, taskSource(held, fast(), fast()))
	select {
	case got := <-sent:
		if got.resolver != 1 || !got.at.Equal(base) {
			t.Fatal(got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("other resolver starved")
	}
	clock.awaitArm(t, base.Add(time.Second))
	clock.advance(time.Second)
	select {
	case got := <-sent:
		if got.resolver != 1 || !got.at.Equal(base.Add(time.Second)) {
			t.Fatal(got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("other resolver starved")
	}
	close(release)
	if r := awaitScheduler(t, done); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestSchedulerAuxiliarySendsShareBudget(t *testing.T) {
	clock := newFakeSchedulerClock()
	base := clock.Now()
	sent := make(chan time.Time, 2)
	s := mustScheduler(t, schedulerConfig{concurrency: 1, resolvers: 1, rate: 10, clock: clock, onSend: func(_ int, at time.Time) { sent <- at }})
	task := &scheduledTask{paced: true, run: func(ctx context.Context, p *sendPermit) taskCompletion {
		p.finish(true)
		next, err := s.wait(ctx, 0)
		if err != nil {
			return taskCompletion{err: err}
		}
		next.finish(true)
		return taskCompletion{}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startScheduler(s, ctx, taskSource(task))
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("initial send missing")
	}
	clock.awaitArm(t, base.Add(100*time.Millisecond))
	clock.advance(100 * time.Millisecond)
	select {
	case at := <-sent:
		if !at.Equal(base.Add(100 * time.Millisecond)) {
			t.Fatal(at)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback send missing")
	}
	if r := awaitScheduler(t, done); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestSchedulerCanceledAuxiliaryRequestReleasesBudget(t *testing.T) {
	clock := newFakeSchedulerClock()
	base := clock.Now()
	sent := make(chan time.Time, 2)
	s := mustScheduler(t, schedulerConfig{concurrency: 1, resolvers: 1, rate: 10, clock: clock, onSend: func(_ int, at time.Time) { sent <- at }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auxCtx, cancelAux := context.WithCancel(ctx)
	defer cancelAux()
	next := &scheduledTask{paced: true, run: func(_ context.Context, p *sendPermit) taskCompletion { p.finish(true); return taskCompletion{} }}
	first := &scheduledTask{paced: true, run: func(_ context.Context, p *sendPermit) taskCompletion {
		p.finish(true)
		_, err := s.wait(auxCtx, 0)
		if !errors.Is(err, context.Canceled) {
			return taskCompletion{err: errors.New("auxiliary request did not cancel")}
		}
		return taskCompletion{next: next}
	}}
	done := startScheduler(s, ctx, taskSource(first))
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("initial send missing")
	}
	clock.awaitArm(t, base.Add(100*time.Millisecond))
	cancelAux()
	clock.awaitArm(t, base.Add(100*time.Millisecond))
	clock.advance(100 * time.Millisecond)
	select {
	case at := <-sent:
		if !at.Equal(base.Add(100 * time.Millisecond)) {
			t.Fatal(at)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request leaked permit")
	}
	if r := awaitScheduler(t, done); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestSchedulerFatalFailureJoinsWorkers(t *testing.T) {
	s := mustScheduler(t, schedulerConfig{concurrency: 2, resolvers: 1})
	started := make(chan struct{})
	failure := errors.New("execution failed")
	first := &scheduledTask{run: func(ctx context.Context, _ *sendPermit) taskCompletion {
		select {
		case <-started:
			return taskCompletion{err: failure}
		case <-ctx.Done():
			return taskCompletion{}
		}
	}}
	second := &scheduledTask{run: func(ctx context.Context, _ *sendPermit) taskCompletion {
		close(started)
		<-ctx.Done()
		return taskCompletion{}
	}}
	r := awaitScheduler(t, startScheduler(s, context.Background(), taskSource(first, second)))
	if !errors.Is(r.err, failure) {
		t.Fatal(r.err)
	}
}
