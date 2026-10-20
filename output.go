package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type logFunc func(string, ...any)

func (log logFunc) printf(format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}

const (
	outputQueueSize     = 64
	outputBufferSize    = 64 << 10
	outputFlushInterval = 100 * time.Millisecond
)

// One owner serializes stdout. Producers queue complete records with bounded
// backpressure. Error bookkeeping never holds a lock across a writer call.
type runOutput struct {
	stderr     io.Writer
	quiet      bool
	ctx        context.Context
	cancel     context.CancelFunc
	records    chan []byte
	done       chan struct{}
	finishOnce sync.Once
	mu         sync.Mutex
	err        error
	stderrMu   sync.Mutex
}

func newRunOutput(ctx context.Context, stdout, stderr io.Writer, quiet bool, cancel context.CancelFunc) *runOutput {
	out := &runOutput{stderr: stderr, quiet: quiet, ctx: ctx, cancel: cancel,
		records: make(chan []byte, outputQueueSize), done: make(chan struct{})}
	go out.writeRecords(stdout)
	return out
}

// checkedWriter also handles short writes on bufio's direct-write path. A
// zero-byte write with no error must become a failure rather than a retry loop.
type checkedWriter struct{ io.Writer }

func (w checkedWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}
func (out *runOutput) fail(err error) {
	out.mu.Lock()
	first := out.err == nil
	if first {
		out.err = err
	}
	out.mu.Unlock()
	if first {
		out.cancel()
	}
}
func (out *runOutput) failure() error {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.err
}
func (out *runOutput) writeRecords(stdout io.Writer) {
	defer close(out.done)
	writer := bufio.NewWriterSize(checkedWriter{stdout}, outputBufferSize)
	ticker := time.NewTicker(outputFlushInterval)
	defer ticker.Stop()
	flush := func() bool {
		if err := writer.Flush(); err != nil {
			out.fail(fmt.Errorf("write stdout (flush): %w", err))
			return false
		}
		return true
	}
	for {
		select {
		case record, ok := <-out.records:
			if !ok {
				flush()
				return
			}
			if _, err := writer.Write(record); err != nil {
				out.fail(fmt.Errorf("write stdout: %w", err))
				return
			}
		case <-ticker.C:
			if !flush() {
				return
			}
		}
	}
}

// finish is called only after all producers have joined. Even on cancellation,
// accepted records are drained and flushed. Underlying writer failures are
// reported; queued records cannot be delivered once that writer has failed.
func (out *runOutput) finish() error {
	out.finishOnce.Do(func() { close(out.records); <-out.done })
	return out.failure()
}
func (out *runOutput) emit(r Result) {
	if out.ctx.Err() != nil {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		out.fail(fmt.Errorf("marshal result: %w", err))
		return
	}
	select {
	case out.records <- append(b, '\n'):
	case <-out.ctx.Done():
	}
}

func (out *runOutput) reportProgress(scanned, resolved *atomic.Uint64, total uint64, start time.Time) {
	n := scanned.Add(1)
	if total <= 256 || n%256 != 0 || n == total {
		return
	}
	out.logf("progress: %d/%d IPs scanned (%.1f%%), %d resolved, %s elapsed",
		n, total, float64(n)/float64(total)*100, resolved.Load(), time.Since(start).Round(time.Millisecond))
}

func (out *runOutput) logf(format string, args ...any) {
	if out.quiet {
		return
	}
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	out.stderrMu.Lock()
	defer out.stderrMu.Unlock()
	if out.failure() != nil {
		return
	}
	if _, err := (checkedWriter{out.stderr}).Write([]byte(line)); err != nil {
		out.fail(fmt.Errorf("write stderr: %w", err))
	}
}
