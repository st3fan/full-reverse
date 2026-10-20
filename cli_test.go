package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/st3fan/full-reverse/ripestat"
)

// Both protocols use the same local port to exercise production TCP fallback.
func localDNS(t testing.TB, handler dns.HandlerFunc) string {
	t.Helper()
	var tcp net.Listener
	var udp net.PacketConn
	// Select the TCP port first so the kernel avoids existing TCP listeners and
	// TIME_WAIT connections. Retry if that port happens to be occupied by UDP.
	for range 20 {
		var err error
		tcp, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err = net.ListenPacket("udp4", tcp.Addr().String())
		if err == nil {
			break
		}
		_ = tcp.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	if udp == nil {
		t.Fatal("could not allocate a shared TCP/UDP fixture port")
	}
	t.Cleanup(func() { _ = udp.Close() })
	t.Cleanup(func() { _ = tcp.Close() })
	for _, server := range []*dns.Server{
		{PacketConn: udp, Handler: handler}, {Listener: tcp, Handler: handler},
	} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		done := make(chan error, 1)
		go func() { done <- server.ActivateAndServe() }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("start DNS server: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("DNS server did not start")
		}
		t.Cleanup(func() {
			if err := server.Shutdown(); err != nil {
				t.Error(err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	return udp.LocalAddr().String()
}

func ptrReply(w dns.ResponseWriter, q *dns.Msg) {
	m := new(dns.Msg).SetReply(q)
	m.Answer = []dns.RR{&dns.PTR{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET},
		Ptr: "host.example.test.",
	}}
	_ = w.WriteMsg(m)
}

func decodeResults(t *testing.T, b *bytes.Buffer) []Result {
	t.Helper()
	var results []Result
	d := json.NewDecoder(b)
	for {
		var result Result
		err := d.Decode(&result)
		if err == io.EOF {
			return results
		}
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
}

func TestCLIResultsRetriesAndTCPFallback(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)
	addr := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if !q.RecursionDesired {
			t.Error("recursive lookup must set RD")
		}
		name := q.Question[0].Name
		network := w.LocalAddr().Network()
		mu.Lock()
		counts[network+":"+name]++
		attempt := counts[network+":"+name]
		mu.Unlock()
		m := new(dns.Msg).SetReply(q)
		switch strings.Split(name, ".")[0] {
		case "1":
			if network == "udp" {
				m.Truncated = true
				_ = w.WriteMsg(m)
				return
			}
		case "2":
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		case "3":
			_ = w.WriteMsg(m) // Successful empty answer is not retried.
			return
		case "4":
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		case "5":
			if attempt == 1 {
				m.Rcode = dns.RcodeServerFailure
				_ = w.WriteMsg(m)
				return
			}
		}
		ptrReply(w, q)
	})
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"192.0.2.0/29", "-d", addr, "-r", "1", "-c", "4"},
		strings.NewReader(""), &stdout, &stderr, cliServices{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	results := decodeResults(t, &stdout)
	if len(results) != 6 {
		t.Fatalf("got %d records, want 6: %+v", len(results), results)
	}
	for _, r := range results {
		if r.Target != "192.0.2.0/29" || r.ASN != nil || r.Prefix != nil || r.ASName != nil || r.ASOrg != nil {
			t.Errorf("metadata changed: %+v", r)
		}
		if r.IP == "192.0.2.4" {
			if !strings.Contains(r.Error, "SERVFAIL") || len(r.PTR) != 0 {
				t.Errorf("failure record: %+v", r)
			}
		} else if len(r.PTR) != 1 || r.PTR[0] != "host.example.test" || r.Error != "" {
			t.Errorf("PTR record: %+v", r)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for key, want := range map[string]int{
		"udp:0.2.0.192.in-addr.arpa.": 1, "udp:1.2.0.192.in-addr.arpa.": 1,
		"tcp:1.2.0.192.in-addr.arpa.": 1, "udp:2.2.0.192.in-addr.arpa.": 1,
		"udp:3.2.0.192.in-addr.arpa.": 1, "udp:4.2.0.192.in-addr.arpa.": 2,
		"udp:5.2.0.192.in-addr.arpa.": 2, "udp:6.2.0.192.in-addr.arpa.": 1,
		"udp:7.2.0.192.in-addr.arpa.": 1,
	} {
		if counts[key] != want {
			t.Errorf("%s attempts = %d, want %d", key, counts[key], want)
		}
	}
	if !strings.Contains(stderr.String(), "8 IPs looked up, 5 resolved, 2 without PTR, 0 unconfirmed, 1 failed") {
		t.Errorf("summary: %s", stderr.String())
	}
}

func TestCLIForwardConfirmation(t *testing.T) {
	addr := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if q.Question[0].Qtype == dns.TypePTR {
			ptrReply(w, q)
			return
		}
		m := new(dns.Msg).SetReply(q)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("192.0.2.1").To4(),
		}}
		_ = w.WriteMsg(m)
	})
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"-f", "-d", addr, "192.0.2.0/30"},
		strings.NewReader(""), &stdout, &stderr, cliServices{})
	results := decodeResults(t, &stdout)
	if code != 0 || len(results) != 1 || results[0].IP != "192.0.2.1" {
		t.Fatalf("exit %d, records %+v, stderr %s", code, results, stderr.String())
	}
	if !strings.Contains(stderr.String(), "3 unconfirmed") {
		t.Fatal(stderr.String())
	}
}

func TestCLIResolverAssignmentAndFallback(t *testing.T) {
	var firstCalls, secondCalls atomic.Int64
	first := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		firstCalls.Add(1)
		m := new(dns.Msg).SetReply(q)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	second := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		secondCalls.Add(1)
		ptrReply(w, q)
	})
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"-d", first, "-d", second, "-c", "1", "-r", "1", "192.0.2.0/30"}, strings.NewReader(""), &stdout, &stderr, cliServices{})
	if code != 0 || len(decodeResults(t, &stdout)) != 4 || firstCalls.Load() != 4 || secondCalls.Load() != 2 {
		t.Fatalf("round-robin: exit %d, first %d, second %d: %s", code, firstCalls.Load(), secondCalls.Load(), stderr.String())
	}
	firstCalls.Store(0)
	secondCalls.Store(0)
	stdout.Reset()
	stderr.Reset()
	services := cliServices{resolvers: func(addrs []string, timeout time.Duration) ([]*dnsResolver, error) {
		if len(addrs) != 0 || timeout != 2500*time.Millisecond {
			t.Errorf("default resolver options: %v, %s", addrs, timeout)
		}
		return []*dnsResolver{newDNSResolver("system", []string{first, second}, timeout)}, nil
	}}
	code = runCLI(context.Background(), []string{"192.0.2.1"}, strings.NewReader(""), &stdout, &stderr, services)
	results := decodeResults(t, &stdout)
	if code != 0 || len(results) != 1 || results[0].Error != "" || firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("system fallback: exit %d, records %+v, first %d, second %d", code, results, firstCalls.Load(), secondCalls.Load())
	}
	if !strings.Contains(stderr.String(), "resolver system: 1 request(s)") {
		t.Fatal(stderr.String())
	}
}

func TestCLIInjectedRIPEAndInputSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/search":
			fmt.Fprint(w, `{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[{"value":"AS64500","description":"EXAMPLE - Example Org"}]}]}}`)
		case "/as":
			fmt.Fprint(w, `{"status":"ok","data":{"holder":"EXAMPLE - Example Org"}}`)
		case "/prefixes":
			fmt.Fprint(w, `{"status":"ok","data":{"prefixes":[{"prefix":"192.0.2.1/32"}]}}`)
		case "/overview":
			fmt.Fprint(w, `{"status":"ok","data":{"resource":"198.51.100.0/24","asns":[{"asn":64501,"holder":"OTHER - Other Org"}]}}`)
		default:
			t.Errorf("unexpected RIPE request: %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	services := cliServices{ripe: &ripestat.Client{
		HTTPClient: server.Client(), SearchURL: server.URL + "/search", ASOverviewURL: server.URL + "/as",
		BaseURL: server.URL + "/prefixes", PrefixOverviewURL: server.URL + "/overview",
	}}
	addr := localDNS(t, ptrReply)
	path := filepath.Join(t.TempDir(), "targets")
	if err := os.WriteFile(path, []byte("198.51.100.1 # file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fileArgs := range [][]string{{"-i", path}, {path}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"-a", "-q", "-d", addr, "-i", "-", "EXAMPLE"}, fileArgs...)
		code := runCLI(context.Background(), args, strings.NewReader("198.51.100.2,198.51.100.3\n"), &stdout, &stderr, services)
		results := decodeResults(t, &stdout)
		if code != 0 || len(results) != 4 || stderr.Len() != 0 {
			t.Fatalf("exit %d, records %+v, stderr %s", code, results, stderr.String())
		}
		for _, r := range results {
			if r.ASN == nil || r.Prefix == nil || r.ASName == nil || r.ASOrg == nil {
				t.Fatalf("missing metadata: %+v", r)
			}
			if r.Target == "EXAMPLE" {
				if *r.ASN != 64500 || *r.Prefix != "192.0.2.1/32" || *r.ASName != "EXAMPLE" || *r.ASOrg != "Example Org" {
					t.Errorf("AS target metadata: %+v", r)
				}
			} else if r.Target != r.IP || *r.ASN != 64501 || *r.Prefix != "198.51.100.0/24" {
				t.Errorf("IP metadata: %+v", r)
			}
		}
	}
}

func TestCLIConcurrentRunsAreIsolated(t *testing.T) {
	addr := localDNS(t, ptrReply)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var stdout, stderr bytes.Buffer
			args := []string{"-d", addr}
			quiet := i%2 == 0
			if quiet {
				args = append(args, "-q")
			}
			code := runCLI(context.Background(), args, strings.NewReader("192.0.2.1\n"), &stdout, &stderr, cliServices{})
			if code != 0 || len(decodeResults(t, &stdout)) != 1 || (stderr.Len() == 0) != quiet {
				t.Errorf("run %d: exit %d, logs %s", i, code, stderr.String())
			}
			if !quiet && !strings.Contains(stderr.String(), "1 request(s)") {
				t.Errorf("resolver metrics leaked across runs: %s", stderr.String())
			}
		}()
	}
	wg.Wait()
}

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestCLIExitCodes(t *testing.T) {
	addr := localDNS(t, ptrReply)
	for _, tt := range []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"-h"}, 0},
		{"unknown flag", []string{"--invalid"}, 2},
		{"bad concurrency", []string{"-c", "0"}, 2},
		{"bad retries", []string{"-r", "-1"}, 2},
		{"empty input", nil, 1},
		{"missing file", []string{"-i", filepath.Join(t.TempDir(), "missing")}, 1},
		{"invalid IPv6 target", []string{"2001:db8::1"}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"-d", addr}, tt.args...)
			if code := runCLI(context.Background(), args, strings.NewReader(""), &stdout, &stderr, cliServices{}); code != tt.want {
				t.Fatalf("exit %d, want %d: %s", code, tt.want, stderr.String())
			}
			if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
	}
	for _, writer := range []io.Writer{failWriter{errors.New("broken output")}, shortWriter{}} {
		var stderr bytes.Buffer
		if code := runCLI(context.Background(), []string{"-d", addr, "192.0.2.1"}, strings.NewReader(""), writer, &stderr, cliServices{}); code != 1 || !strings.Contains(stderr.String(), "write stdout") {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
	}
	if code := runCLI(context.Background(), []string{"-d", addr, "192.0.2.1"}, strings.NewReader(""), io.Discard, failWriter{errors.New("broken stderr")}, cliServices{}); code != 1 {
		t.Fatalf("stderr failure exit %d", code)
	}
	var stderr bytes.Buffer
	services := cliServices{resolvers: func([]string, time.Duration) ([]*dnsResolver, error) {
		return nil, errors.New("resolver setup failed")
	}}
	if code := runCLI(context.Background(), []string{"192.0.2.1"}, strings.NewReader(""), io.Discard, &stderr, services); code != 1 || !strings.Contains(stderr.String(), "resolver setup failed") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func awaitExit(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(3 * time.Second):
		t.Fatal("CLI did not stop promptly")
		return -1
	}
}

func TestCLICancelBlockedInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	done := make(chan int, 1)
	reader := &observedReadCloser{ReadCloser: r, started: make(chan struct{})}
	go func() { done <- runCLI(ctx, nil, reader, io.Discard, io.Discard, cliServices{}) }()
	select {
	case <-reader.started:
	case <-time.After(3 * time.Second):
		t.Fatal("input read did not start")
	}
	cancel()
	if code := awaitExit(t, done); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

type observedReadCloser struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (r *observedReadCloser) Read(b []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.ReadCloser.Read(b)
}

func TestCLIDefaultRetries(t *testing.T) {
	var calls atomic.Int64
	addr := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		calls.Add(1)
		m := new(dns.Msg).SetReply(q)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"-d", addr, "192.0.2.1"}, strings.NewReader(""), &stdout, &stderr, cliServices{})
	results := decodeResults(t, &stdout)
	if code != 0 || calls.Load() != 5 || len(results) != 1 || results[0].Error == "" {
		t.Fatalf("default retries: exit %d, attempts %d, records %+v", code, calls.Load(), results)
	}
}

func TestCLICancelDNSAndEnumeration(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			var once sync.Once
			var calls atomic.Int64
			addr := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
				calls.Add(1)
				if network == "tcp" && w.LocalAddr().Network() == "udp" {
					m := new(dns.Msg).SetReply(q)
					m.Truncated = true
					_ = w.WriteMsg(m)
					return
				}
				once.Do(func() { close(started) })
				<-ctx.Done() // Hold the connection open without replying.
			})
			done := make(chan int, 1)
			go func() {
				done <- runCLI(ctx, []string{"-d", addr, "-c", "1", "-t", "1m", "0.0.0.0/0"}, strings.NewReader(""), io.Discard, io.Discard, cliServices{})
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("query did not start")
			}
			cancel()
			if code := awaitExit(t, done); code != 1 {
				t.Fatalf("exit %d", code)
			}
			want := int64(1)
			if network == "tcp" {
				want = 2
			}
			if calls.Load() != want {
				t.Fatalf("canceled run sent %d queries, want %d", calls.Load(), want)
			}
		})
	}
}

func TestCLICancelRIPE(t *testing.T) {
	for _, args := range [][]string{{"AS64500"}, {"-a", "-c", "4", "192.0.2.0/24"}} {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{}, 1)
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			started <- struct{}{}
			<-r.Context().Done()
		}))
		client := &ripestat.Client{HTTPClient: server.Client(), ASOverviewURL: server.URL, PrefixOverviewURL: server.URL}
		done := make(chan int, 1)
		go func() {
			done <- runCLI(ctx, args, strings.NewReader(""), io.Discard, io.Discard, cliServices{ripe: client})
		}()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			cancel()
			server.Close()
			t.Fatal("RIPE request did not start")
		}
		cancel()
		code := awaitExit(t, done)
		server.Close()
		if code != 1 || calls.Load() != 1 {
			t.Fatalf("canceled RIPE: exit %d, requests %d", code, calls.Load())
		}
	}
}

func TestCLIReportsInputAndRIPEFailures(t *testing.T) {
	var stderr bytes.Buffer
	code := runCLI(context.Background(), nil, errorReader{}, io.Discard, &stderr, cliServices{})
	if code != 1 || !strings.Contains(stderr.String(), "input failed") {
		t.Fatalf("input failure: exit %d: %s", code, stderr.String())
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	stderr.Reset()
	services := cliServices{ripe: &ripestat.Client{HTTPClient: server.Client(), ASOverviewURL: server.URL}}
	code = runCLI(context.Background(), []string{"AS64500"}, strings.NewReader(""), io.Discard, &stderr, services)
	if code != 1 || !strings.Contains(stderr.String(), "503") {
		t.Fatalf("RIPE failure: exit %d: %s", code, stderr.String())
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("input failed") }
