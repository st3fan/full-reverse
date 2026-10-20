package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRunOutput(t *testing.T, stdout io.Writer) (*runOutput, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := newRunOutput(ctx, stdout, io.Discard, true, cancel)
	t.Cleanup(func() { cancel(); out.finish() })
	return out, ctx, cancel
}

func TestOutputConcurrentCompleteRecords(t *testing.T) {
	var buffer bytes.Buffer
	out, _, _ := testRunOutput(t, &buffer)
	var producers sync.WaitGroup
	const count = 200
	for producer := range 8 {
		producers.Go(func() {
			for sequence := range count {
				out.emit(Result{IP: fmt.Sprint(producer), Target: fmt.Sprint(sequence), PTR: []string{"host.example.test"}})
			}
		})
	}
	producers.Wait()
	if err := out.finish(); err != nil {
		t.Fatal(err)
	}
	results := decodeResults(t, &buffer)
	if len(results) != 8*count {
		t.Fatalf("records=%d", len(results))
	}
	next := map[string]int{}
	for _, r := range results {
		if r.Target != fmt.Sprint(next[r.IP]) {
			t.Fatalf("producer order/interleaving: %+v next=%v", r, next)
		}
		next[r.IP]++
	}
}

func TestOutputTimedFlushAndImmediateDiagnostics(t *testing.T) {
	stdout := &recordWriter{records: make(chan []byte, 2)}
	stderr := &recordWriter{records: make(chan []byte, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := newRunOutput(ctx, stdout, stderr, false, cancel)
	defer out.finish()
	out.emit(Result{IP: "192.0.2.1", PTR: []string{}})
	out.logf("diagnostic")
	select {
	case line := <-stderr.records:
		if !bytes.Contains(line, []byte("diagnostic")) {
			t.Fatalf("stderr=%s", line)
		}
	default:
		t.Fatal("diagnostic was buffered")
	}
	select {
	case line := <-stdout.records:
		var result Result
		if err := json.Unmarshal(line, &result); err != nil || result.IP != "192.0.2.1" {
			t.Fatalf("stdout=%s err=%v", line, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("record was delayed until shutdown")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestOutputWriteAndFinalFlushFailures(t *testing.T) {
	injected := errors.New("injected output failure")
	for _, test := range []struct {
		name   string
		writer io.Writer
		large  bool
		want   error
	}{
		{"large write", failWriter{injected}, true, injected},
		{"large short write", shortWriter{}, true, io.ErrShortWrite},
		{"large zero write", zeroWriter{}, true, io.ErrShortWrite},
		{"final flush", failWriter{injected}, false, injected},
		{"final short flush", shortWriter{}, false, io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, ctx, _ := testRunOutput(t, test.writer)
			result := Result{IP: "192.0.2.1", PTR: []string{}}
			if test.large {
				result.PTR = []string{strings.Repeat("x", outputBufferSize+1)}
			}
			out.emit(result)
			if test.large {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("write failure did not cancel")
				}
			}
			err := out.finish()
			if !errors.Is(err, test.want) || !strings.Contains(err.Error(), "write stdout") || (!test.large && !strings.Contains(err.Error(), "flush")) {
				t.Fatalf("error=%v", err)
			}
			select {
			case <-ctx.Done():
			default:
				t.Fatal("flush failure did not cancel")
			}
		})
	}
}

type blockedOutput struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	bytes.Buffer
}

func (w *blockedOutput) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.started); <-w.release })
	return w.Buffer.Write(b)
}

func TestOutputBackpressureCancellationAndAcceptedDrain(t *testing.T) {
	writer := &blockedOutput{started: make(chan struct{}), release: make(chan struct{})}
	out, _, cancel := testRunOutput(t, writer)
	var release sync.Once
	unblock := func() { release.Do(func() { close(writer.release) }) }
	t.Cleanup(unblock)
	// A large first record blocks the owner in the underlying write, leaving a
	// finite queue for other producers. Diagnostics and cancellation stay free.
	out.emit(Result{IP: "first", PTR: []string{strings.Repeat("x", outputBufferSize+1)}})
	awaitSignal(t, writer.started)
	for i := range outputQueueSize {
		out.emit(Result{IP: fmt.Sprint(i), PTR: []string{}})
	}
	if len(out.records) != outputQueueSize {
		t.Fatalf("queue=%d", len(out.records))
	}
	rejected := make(chan struct{})
	go func() { out.emit(Result{IP: "canceled", PTR: []string{}}); close(rejected) }()
	cancel()
	awaitSignal(t, rejected)
	finished := make(chan error, 1)
	go func() { finished <- out.finish() }()
	unblock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accepted records did not drain")
	}
	results := decodeResults(t, &writer.Buffer)
	if len(results) != outputQueueSize+1 {
		t.Fatalf("drained=%d", len(results))
	}
	for _, r := range results {
		if r.IP == "canceled" {
			t.Fatal("blocked producer bypassed cancellation")
		}
	}
}

func TestOutputStreamingFailureCancelsDNS(t *testing.T) {
	var queries atomic.Int64
	server := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if queries.Add(1) == 1 {
			ptrReply(w, q)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	start := time.Now()
	code := runCLI(ctx, []string{"-d", server, "-c", "1", "-t", "10s", "192.0.2.0/24"}, strings.NewReader(""), failWriter{errors.New("stream failed")}, &stderr, cliServices{})
	if code != 1 || !strings.Contains(stderr.String(), "stream failed") {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	if time.Since(start) > time.Second || queries.Load() > 2 {
		t.Fatalf("output failure did not stop DNS promptly: elapsed=%s queries=%d", time.Since(start), queries.Load())
	}
}
