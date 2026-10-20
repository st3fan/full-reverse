package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/st3fan/full-reverse/ripestat"
)

type cachedRIPE struct {
	ripeClient
	prefixes map[netip.Prefix]uint32
}

func (r cachedRIPE) CachedPrefixASNs() map[netip.Prefix]uint32 { return r.prefixes }

type recordWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	records chan []byte
}

func (w *recordWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.buffer.Write(b)
	// Current output writes complete records; the buffered writer added in #15
	// may combine them. Parse lines so this fixture also handles batched writes.
	for {
		data := w.buffer.Bytes()
		index := bytes.IndexByte(data, '\n')
		if index < 0 {
			break
		}
		line := append([]byte(nil), data[:index+1]...)
		w.buffer.Next(index + 1)
		w.records <- line
	}
	return len(b), nil
}

func TestMetadataDoesNotOccupyDNSConcurrency(t *testing.T) {
	blocked, release := make(chan struct{}), make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/overview" {
			close(blocked)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			fmt.Fprint(w, `{"status":"ok","data":{"resource":"192.0.2.0/24","asns":[{"asn":64500,"holder":"SLOW - Example"}]}}`)
		} else {
			fmt.Fprint(w, `{"status":"ok","data":{"holder":"FAST - Example"}}`)
		}
	}))
	defer httpServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queries := make(chan string, 3)
	dnsServer := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { queries <- q.Question[0].Name; ptrReply(w, q) })
	client := &ripestat.Client{HTTPClient: httpServer.Client(), PrefixOverviewURL: httpServer.URL + "/overview", ASOverviewURL: httpServer.URL + "/as"}
	services := cliServices{ripe: cachedRIPE{client, map[netip.Prefix]uint32{netip.MustParsePrefix("198.51.100.0/24"): 64501}}}
	stdout := &recordWriter{records: make(chan []byte, 3)}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{"-a", "-c", "1", "-d", dnsServer, "192.0.2.1", "198.51.100.1", "198.51.100.2"}, strings.NewReader(""), stdout, &stderr, services)
	}()
	awaitSignal(t, blocked)
	for range 3 {
		select {
		case <-queries:
		case <-time.After(2 * time.Second):
			t.Fatal("slow HTTP consumed the DNS slot")
		}
	}
	for range 2 {
		select {
		case line := <-stdout.records:
			if !bytes.Contains(line, []byte(`"asn":64501`)) || !bytes.Contains(line, []byte(`"as_name":"FAST"`)) {
				t.Fatalf("metadata missing: %s", line)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("unrelated metadata waited behind prefix HTTP")
		}
	}
	close(release)
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, &stderr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not drain")
	}
	line := <-stdout.records
	if !bytes.Contains(line, []byte(`"asn":64500`)) || !bytes.Contains(line, []byte(`"target":"192.0.2.1"`)) {
		t.Fatalf("joined record: %s", line)
	}
}

func TestMetadataAdmissionBoundAndCancellation(t *testing.T) {
	started := make(chan struct{})
	var api, queries atomic.Int64
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if api.Add(1) == 1 {
			close(started)
		}
		<-r.Context().Done()
	}))
	defer httpServer.Close()
	fullWindow := make(chan struct{})
	dnsServer := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if queries.Add(1) == int64(metadataWindow(1)) {
			close(fullWindow)
		}
		ptrReply(w, q)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{"-a", "-c", "1", "-d", dnsServer, "0.0.0.0/0"}, strings.NewReader(""), io.Discard, &stderr, cliServices{ripe: &ripestat.Client{HTTPClient: httpServer.Client(), PrefixOverviewURL: httpServer.URL}})
	}()
	awaitSignal(t, started)
	awaitSignal(t, fullWindow)
	cancel()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit %d: %s", code, &stderr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline cancellation leaked workers")
	}
	if queries.Load() != int64(metadataWindow(1)) || api.Load() != 1 {
		t.Fatalf("unbounded work: DNS=%d HTTP=%d", queries.Load(), api.Load())
	}
}

func TestMetadataFailureKeepsDNSErrorAndEmptyAnswerBehavior(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	defer httpServer.Close()
	dnsServer := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg).SetReply(q)
		if strings.HasPrefix(q.Question[0].Name, "1.") {
			reply.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(reply)
	})
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"-a", "-r", "0", "-d", dnsServer, "192.0.2.0/31"}, strings.NewReader(""), &stdout, &stderr, cliServices{ripe: &ripestat.Client{HTTPClient: httpServer.Client(), PrefixOverviewURL: httpServer.URL}})
	results := decodeResults(t, &stdout)
	if code != 0 || len(results) != 1 || results[0].IP != "192.0.2.1" || results[0].Error == "" || results[0].ASN != nil || !strings.Contains(stderr.String(), "warning: AS lookup") {
		t.Fatalf("exit %d results=%+v stderr=%s", code, results, &stderr)
	}
}
