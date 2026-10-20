package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/st3fan/full-reverse/ripestat"
)

const benchmarkTimeout = 250 * time.Millisecond

var benchmarkPrefix = netip.MustParsePrefix("192.0.2.0/24")

type lookupScenario struct {
	name                    string
	forward, metadata, warm bool
}

var lookupScenarios = []lookupScenario{
	{name: "fast"}, {name: "delayed"}, {name: "loss"}, {name: "duplicates"},
	{name: "reordered"}, {name: "late"}, {name: "negative"}, {name: "truncated"},
	{name: "forward", forward: true},
	{name: "asn-cold", metadata: true}, {name: "asn-warm", metadata: true, warm: true},
}

// All network destinations are dynamically allocated loopback endpoints.
// The documentation addresses below are DNS question data, never scan endpoints.
type lookupFixture struct {
	scenario                                    lookupScenario
	prefix                                      netip.Prefix
	base                                        uint32
	count                                       int
	addr                                        string
	client                                      *ripestat.Client
	httpServer                                  *httptest.Server
	ptrAttempts, aAttempts                      []atomic.Uint32
	udpPTR, udpA, tcp, retries, api, duplicates atomic.Uint64
	active, peakActive                          atomic.Int64
	handlers                                    sync.WaitGroup
	mu                                          sync.Mutex
	err                                         error
}

func newLookupFixture(t testing.TB, scenario lookupScenario, prefix netip.Prefix) *lookupFixture {
	t.Helper()
	f := &lookupFixture{scenario: scenario, prefix: prefix, count: 1 << (32 - prefix.Bits())}
	f.base = binary.BigEndian.Uint32(prefix.Addr().AsSlice())
	f.ptrAttempts = make([]atomic.Uint32, f.count)
	f.aAttempts = make([]atomic.Uint32, f.count)
	f.addr = localDNS(t, f.serveDNS)
	f.httpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.api.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/prefixes":
			fmt.Fprintf(w, `{"status":"ok","data":{"prefixes":[{"prefix":%q}]}}`, prefix.String())
		case "/as":
			fmt.Fprint(w, `{"status":"ok","data":{"holder":"BENCHMARK - Synthetic fixture"}}`)
		case "/overview":
			fmt.Fprintf(w, `{"status":"ok","data":{"resource":%q,"announced":true,"asns":[{"asn":64500,"holder":"BENCHMARK - Synthetic fixture"}]}}`, prefix.String())
		default:
			f.fail(fmt.Errorf("unexpected HTTP path %q", r.URL.Path))
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.httpServer.Close)
	return f
}

func (f *lookupFixture) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		f.err = err
	}
}

// Prepare fresh per-run caches and counters outside the measured interval.
func (f *lookupFixture) prepare(t testing.TB) {
	t.Helper()
	f.handlers.Wait()
	for i := range f.ptrAttempts {
		f.ptrAttempts[i].Store(0)
		f.aAttempts[i].Store(0)
	}
	f.udpPTR.Store(0)
	f.udpA.Store(0)
	f.tcp.Store(0)
	f.retries.Store(0)
	f.api.Store(0)
	f.duplicates.Store(0)
	f.active.Store(0)
	f.peakActive.Store(0)
	f.mu.Lock()
	f.err = nil
	f.mu.Unlock()
	f.client = &ripestat.Client{
		HTTPClient: f.httpServer.Client(), BaseURL: f.httpServer.URL + "/prefixes",
		ASOverviewURL: f.httpServer.URL + "/as", PrefixOverviewURL: f.httpServer.URL + "/overview",
		CacheDir: t.TempDir(), CacheTTL: time.Hour,
	}
	if f.scenario.warm {
		if _, err := f.client.AnnouncedPrefixes(context.Background(), "AS64500"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.client.ASOverview(context.Background(), "AS64500"); err != nil {
			t.Fatal(err)
		}
		f.api.Store(0)
	}
}

func (f *lookupFixture) index(q dns.Question) (int, error) {
	var value uint64
	var err error
	if q.Qtype == dns.TypePTR {
		parts := strings.Split(q.Name, ".")
		if len(parts) != 7 || parts[4] != "in-addr" || parts[5] != "arpa" {
			return 0, fmt.Errorf("unexpected PTR question %q", q.Name)
		}
		for i := 3; i >= 0; i-- {
			v, e := strconv.ParseUint(parts[i], 10, 8)
			if e != nil {
				return 0, e
			}
			value = value<<8 | v
		}
	} else if q.Qtype == dns.TypeA {
		value, err = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(q.Name, "host-"), ".example.test."), 10, 32)
	} else {
		return 0, fmt.Errorf("unexpected question type %d", q.Qtype)
	}
	if err != nil || value < uint64(f.base) || value >= uint64(f.base)+uint64(f.count) {
		return 0, fmt.Errorf("question outside fixture: %s", q.Name)
	}
	return int(value - uint64(f.base)), nil
}

func (f *lookupFixture) serveDNS(w dns.ResponseWriter, q *dns.Msg) {
	f.handlers.Add(1)
	defer f.handlers.Done()
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for old := f.peakActive.Load(); n > old; old = f.peakActive.Load() {
		if f.peakActive.CompareAndSwap(old, n) {
			break
		}
	}
	if len(q.Question) != 1 || !q.RecursionDesired || q.Question[0].Qclass != dns.ClassINET {
		f.fail(fmt.Errorf("invalid question: %v", q))
		return
	}
	question := q.Question[0]
	index, err := f.index(question)
	if err != nil {
		f.fail(err)
		return
	}
	tcp := w.LocalAddr().Network() == "tcp"
	var attempt uint32
	if tcp {
		f.tcp.Add(1)
	} else if question.Qtype == dns.TypePTR {
		f.udpPTR.Add(1)
		attempt = f.ptrAttempts[index].Add(1)
	} else {
		f.udpA.Add(1)
		attempt = f.aAttempts[index].Add(1)
	}
	if attempt > 1 {
		f.retries.Add(1)
	}
	m := new(dns.Msg).SetReply(q)
	if question.Qtype == dns.TypePTR {
		switch f.scenario.name {
		case "delayed":
			time.Sleep(2 * time.Millisecond)
		case "reordered":
			time.Sleep(time.Duration(7-index%8) * time.Millisecond)
		case "loss":
			if index%16 == 0 && attempt == 1 {
				return
			}
		case "late":
			if index%16 == 0 && attempt == 1 {
				time.Sleep(benchmarkTimeout + benchmarkTimeout/2)
			}
		case "negative":
			switch index % 4 {
			case 0:
				m.Rcode = dns.RcodeNameError
			case 1: // Successful empty answer.
			case 2:
				m.Rcode = dns.RcodeServerFailure
			case 3:
				f.addPTR(m, question, index)
			}
			if err := w.WriteMsg(m); err != nil {
				f.fail(err)
			}
			return
		case "truncated":
			if !tcp {
				m.Truncated = true
				if err := w.WriteMsg(m); err != nil {
					f.fail(err)
				}
				return
			}
		}
		f.addPTR(m, question, index)
	} else {
		ip := f.ip(index)
		if index%2 != 0 {
			ip = f.ip(index - 1)
		}
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IP(ip.AsSlice())}}
	}
	if err := w.WriteMsg(m); err != nil {
		// The late UDP response can arrive after the client has closed its socket.
		f.fail(err)
		return
	}
	if f.scenario.name == "duplicates" {
		if err := w.WriteMsg(m); err != nil {
			f.fail(err)
		}
		f.duplicates.Add(1)
	}
}

func (f *lookupFixture) ip(index int) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], f.base+uint32(index))
	return netip.AddrFrom4(b)
}

func (f *lookupFixture) addPTR(m *dns.Msg, q dns.Question, index int) {
	m.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET}, Ptr: f.hostname(index) + "."}}
}

func (f *lookupFixture) hostname(index int) string {
	return fmt.Sprintf("host-%d.example.test", f.base+uint32(index))
}

func (f *lookupFixture) expected(index int) (emit, failed bool) {
	if f.scenario.name == "negative" {
		return index%4 >= 2, index%4 == 2
	}
	if f.scenario.forward {
		return index%2 == 0, false
	}
	return true, false
}

// Validate streaming JSONL without retaining results. The fixture's seen bitmap
// is allocated before timing and catches duplicates as well as missing records.
type benchmarkVerifier struct {
	f               *lookupFixture
	seen            []bool
	pending         []byte
	records, failed int
}

func (v *benchmarkVerifier) Write(b []byte) (int, error) {
	v.pending = append(v.pending, b...)
	for {
		n := bytes.IndexByte(v.pending, '\n')
		if n < 0 {
			break
		}
		if err := v.record(v.pending[:n]); err != nil {
			return 0, err
		}
		v.pending = v.pending[n+1:]
	}
	if len(v.pending) > 64<<10 {
		return 0, fmt.Errorf("oversized incomplete JSONL record")
	}
	return len(b), nil
}

func (v *benchmarkVerifier) record(b []byte) error {
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(r.IP)
	if err != nil || !ip.Is4() || !v.f.prefix.Contains(ip) {
		return fmt.Errorf("unexpected result IP %q", r.IP)
	}
	index := int(binary.BigEndian.Uint32(ip.AsSlice()) - v.f.base)
	emit, failed := v.f.expected(index)
	if !emit || v.seen[index] {
		return fmt.Errorf("unexpected or duplicate result for %s", ip)
	}
	v.seen[index] = true
	v.records++
	if r.Target != v.f.prefix.String() || r.PTR == nil {
		return fmt.Errorf("invalid target/PTR fields for %s", ip)
	}
	if failed {
		v.failed++
		if !strings.Contains(r.Error, "SERVFAIL") || len(r.PTR) != 0 {
			return fmt.Errorf("invalid failure for %s", ip)
		}
	} else if r.Error != "" || len(r.PTR) != 1 || r.PTR[0] != v.f.hostname(index) {
		return fmt.Errorf("incorrect PTR result for %s: %+v", ip, r)
	}
	if v.f.scenario.metadata {
		if r.ASN == nil || *r.ASN != 64500 || r.Prefix == nil || *r.Prefix != v.f.prefix.String() ||
			r.ASName == nil || *r.ASName != "BENCHMARK" || r.ASOrg == nil || *r.ASOrg != "Synthetic fixture" {
			return fmt.Errorf("incorrect ASN metadata for %s", ip)
		}
	} else if r.ASN != nil || r.Prefix != nil || r.ASName != nil || r.ASOrg != nil {
		return fmt.Errorf("unexpected metadata for %s", ip)
	}
	return nil
}

func (f *lookupFixture) verify(t testing.TB, v *benchmarkVerifier) {
	t.Helper()
	f.handlers.Wait() // Late replies must finish before resetting the fixture.
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.pending) != 0 {
		t.Fatal("incomplete final JSONL record")
	}
	for i := range f.count {
		emit, _ := f.expected(i)
		if v.seen[i] != emit {
			t.Fatalf("missing or unexpected record for %s", f.ip(i))
		}
		want := uint32(1)
		if (f.scenario.name == "loss" || f.scenario.name == "late") && i%16 == 0 {
			want = 2
		}
		if f.scenario.name == "negative" && i%4 == 2 {
			want = 2
		}
		if got := f.ptrAttempts[i].Load(); got != want {
			t.Fatalf("PTR attempts for %s: %d, want %d", f.ip(i), got, want)
		}
		wantA := uint32(0)
		if f.scenario.forward {
			wantA = 1
		}
		if got := f.aAttempts[i].Load(); got != wantA {
			t.Fatalf("A attempts for %s: %d, want %d", f.ip(i), got, wantA)
		}
	}
	wantTCP := uint64(0)
	if f.scenario.name == "truncated" {
		wantTCP = uint64(f.count)
	}
	if f.tcp.Load() != wantTCP {
		t.Fatalf("TCP queries %d, want %d", f.tcp.Load(), wantTCP)
	}
	wantAPI := uint64(0)
	if f.scenario.metadata && !f.scenario.warm {
		wantAPI = 1
	}
	if f.api.Load() != wantAPI {
		t.Fatalf("API requests %d, want %d", f.api.Load(), wantAPI)
	}
	wantDuplicates := uint64(0)
	if f.scenario.name == "duplicates" {
		wantDuplicates = uint64(f.count)
	}
	if f.duplicates.Load() != wantDuplicates {
		t.Fatalf("duplicate replies %d, want %d", f.duplicates.Load(), wantDuplicates)
	}
}

// Process-wide sampling includes both engine and in-process fixture overhead.
// It measures observed peaks, not an engine-only memory bound.
type benchmarkMemory struct {
	heap                   uint64
	maxHeap, maxGoroutines atomic.Uint64
	stop, done             chan struct{}
}

func sampleBenchmarkMemory() *benchmarkMemory {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	m := &benchmarkMemory{heap: stats.HeapAlloc, stop: make(chan struct{}), done: make(chan struct{})}
	m.maxHeap.Store(stats.HeapAlloc)
	m.maxGoroutines.Store(uint64(runtime.NumGoroutine()))
	go func() {
		defer close(m.done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.sample()
			case <-m.stop:
				return
			}
		}
	}()
	return m
}

func (m *benchmarkMemory) sample() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	for old := m.maxHeap.Load(); stats.HeapAlloc > old; old = m.maxHeap.Load() {
		if m.maxHeap.CompareAndSwap(old, stats.HeapAlloc) {
			break
		}
	}
	n := uint64(runtime.NumGoroutine())
	for old := m.maxGoroutines.Load(); n > old; old = m.maxGoroutines.Load() {
		if m.maxGoroutines.CompareAndSwap(old, n) {
			break
		}
	}
}

func runLookupBenchmark(b *testing.B, s lookupScenario, prefix netip.Prefix, concurrency int) {
	b.StopTimer()
	f := newLookupFixture(b, s, prefix)
	b.ReportAllocs()
	var elapsed time.Duration
	var udpPTR, udpA, tcp, retries, api, records, failures, peakHeap, peakGoroutines uint64
	var peakActive int64
	for range b.N {
		f.prepare(b)
		v := &benchmarkVerifier{f: f, seen: make([]bool, f.count)}
		memory := sampleBenchmarkMemory()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		opts := lookupOptions{dnsServers: []string{f.addr}, concurrency: concurrency, retries: 1, timeout: benchmarkTimeout,
			lookupAS: s.metadata, forwardConfirmedOnly: s.forward, quiet: true}
		b.StartTimer()
		start := time.Now()
		err := runLookups(ctx, opts, []string{prefix.String()}, v, io.Discard, cliServices{ripe: f.client})
		elapsed += time.Since(start)
		b.StopTimer()
		cancel()
		memory.sample()
		close(memory.stop)
		<-memory.done
		if err != nil {
			b.Fatal(err)
		}
		f.verify(b, v)
		peakHeap = max(peakHeap, memory.maxHeap.Load()-memory.heap)
		peakGoroutines = max(peakGoroutines, memory.maxGoroutines.Load())
		peakActive = max(peakActive, f.peakActive.Load())
		udpPTR += f.udpPTR.Load()
		udpA += f.udpA.Load()
		tcp += f.tcp.Load()
		retries += f.retries.Load()
		api += f.api.Load()
		records += uint64(v.records)
		failures += uint64(v.failed)
	}
	perRun := float64(b.N)
	b.ReportMetric(float64(f.count)*perRun/elapsed.Seconds(), "addresses/s")
	for name, value := range map[string]uint64{"udp-ptr/op": udpPTR, "udp-a/op": udpA, "tcp/op": tcp, "retries/op": retries,
		"api/op": api, "records/op": records, "errors/op": failures} {
		b.ReportMetric(float64(value)/perRun, name)
	}
	b.ReportMetric(1, "complete")
	b.ReportMetric(float64(peakHeap), "peak-heap-delta-B")
	b.ReportMetric(float64(peakGoroutines), "peak-goroutines")
	b.ReportMetric(float64(peakActive), "peak-handlers")
}

func BenchmarkLookup(b *testing.B) {
	for _, s := range lookupScenarios {
		b.Run(s.name, func(b *testing.B) {
			for _, c := range []int{32, 64, 128, 256} {
				b.Run(fmt.Sprintf("c%d", c), func(b *testing.B) { runLookupBenchmark(b, s, benchmarkPrefix, c) })
			}
		})
	}
}

// Fixed concurrency, larger address sets, and streaming verification expose
// growth in allocation/observed memory without retaining the JSONL result set.
func BenchmarkLookupScale(b *testing.B) {
	for _, prefix := range []string{"198.18.0.0/22", "198.18.0.0/20", "198.18.0.0/18"} {
		p := netip.MustParsePrefix(prefix)
		b.Run(fmt.Sprintf("n%d", 1<<(32-p.Bits())), func(b *testing.B) {
			runLookupBenchmark(b, lookupScenario{name: "delayed"}, p, 32)
		})
	}
}

// Keep fixture correctness in ordinary CI as well as the explicit benchmark run.
func TestLookupBenchmarkScenarios(t *testing.T) {
	for _, s := range lookupScenarios {
		t.Run(s.name, func(t *testing.T) {
			f := newLookupFixture(t, s, netip.MustParsePrefix("192.0.2.0/28"))
			f.prepare(t)
			v := &benchmarkVerifier{f: f, seen: make([]bool, f.count)}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := runLookups(ctx, lookupOptions{dnsServers: []string{f.addr}, concurrency: 8, retries: 1, timeout: benchmarkTimeout,
				lookupAS: s.metadata, forwardConfirmedOnly: s.forward, quiet: true}, []string{f.prefix.String()}, v, io.Discard, cliServices{ripe: f.client})
			if err != nil {
				t.Fatal(err)
			}
			f.verify(t, v)
		})
	}
}

func TestBenchmarkVerifierRejectsCorruptResults(t *testing.T) {
	f := &lookupFixture{prefix: benchmarkPrefix, count: 256,
		base: binary.BigEndian.Uint32(benchmarkPrefix.Addr().AsSlice())}
	valid := Result{IP: f.ip(0).String(), Target: f.prefix.String(), PTR: []string{f.hostname(0)}}
	for _, tt := range []struct {
		name   string
		change func(*Result)
	}{
		{"wrong target", func(r *Result) { r.Target = "other" }},
		{"wrong PTR", func(r *Result) { r.PTR = []string{"wrong.example.test"} }},
		{"missing PTR array", func(r *Result) { r.PTR = nil }},
		{"wrong error", func(r *Result) { r.Error = "unexpected failure" }},
		{"wrong IP", func(r *Result) { r.IP = "203.0.113.1" }},
		{"unexpected metadata", func(r *Result) { asn := uint32(64500); r.ASN = &asn }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := &benchmarkVerifier{f: f, seen: make([]bool, f.count)}
			r := valid
			tt.change(&r)
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.record(b); err == nil {
				t.Fatal("accepted corrupt record")
			}
		})
	}
	v := &benchmarkVerifier{f: f, seen: make([]bool, f.count)}
	b, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	// Accept split writes, then reject a second copy of the same result.
	if _, err := v.Write(b[:len(b)/2]); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Write(b[len(b)/2:]); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Write(b); err == nil {
		t.Fatal("accepted duplicate result")
	}
}
