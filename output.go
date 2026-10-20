package main

import (
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

// runOutput owns per-run output synchronization and the first write error.
// Writes remain unbuffered; output queues and batching belong to a later change.
type runOutput struct {
	stdout, stderr io.Writer
	quiet          bool
	cancel         context.CancelFunc
	mu             sync.Mutex
	err            error
}

func (out *runOutput) write(w io.Writer, stream string, b []byte) {
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.err != nil {
		return
	}
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		out.err = fmt.Errorf("write %s: %w", stream, err)
		out.cancel()
	}
}

func (out *runOutput) failure() error {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.err
}

func (out *runOutput) emit(r Result) {
	b, err := json.Marshal(r)
	if err != nil {
		out.logf("error: marshal: %v", err)
		return
	}
	out.write(out.stdout, "stdout", append(b, '\n'))
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
	out.write(out.stderr, "stderr", []byte(line))
}
