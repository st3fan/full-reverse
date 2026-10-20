package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestScheduledWireBudgetIncludesRetriesForwardAndTCP(t *testing.T) {
	var mu sync.Mutex
	attempts := map[string]int{}
	count := 0
	server := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		count++
		key := fmt.Sprint(q.Question[0])
		attempts[key]++
		attempt := attempts[key]
		mu.Unlock()
		reply := new(dns.Msg).SetReply(q)
		_, tcp := w.RemoteAddr().(*net.TCPAddr)
		if q.Question[0].Qtype == dns.TypePTR {
			if !tcp && attempt == 1 {
				reply.Rcode = dns.RcodeServerFailure
			} else if !tcp {
				reply.Truncated = true
			} else {
				ptrReply(w, q)
				return
			}
		} else {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1").To4()}}
		}
		_ = w.WriteMsg(reply)
	})
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := runCLI(context.Background(), []string{"-d", server, "-c", "2", "-r", "1", "-t", "2s", "-f", "--rate", "20", "192.0.2.0/31"}, strings.NewReader(""), &stdout, &stderr, cliServices{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	// Two addresses each send failed PTR, truncated PTR, TCP PTR, and A.
	mu.Lock()
	got := count
	mu.Unlock()
	if got != 8 {
		t.Fatalf("wire sends=%d, want 8", got)
	}
	if elapsed := time.Since(start); elapsed < 340*time.Millisecond {
		t.Fatalf("shared 20/s budget bypassed: %s", elapsed)
	}
	results := decodeResults(t, &stdout)
	if len(results) != 1 || results[0].IP != "192.0.2.1" || results[0].Error != "" {
		t.Fatalf("results=%+v", results)
	}
}

func TestInitialPacingWaitDoesNotUseAttemptTimeout(t *testing.T) {
	server := localDNS(t, ptrReply)
	var stdout, stderr bytes.Buffer
	// Waiting 100ms for the second grant must not consume its 40ms timeout.
	code := runCLI(context.Background(), []string{"-d", server, "-c", "2", "-r", "0", "-t", "40ms", "--resolver-rate", "10", "192.0.2.0/31"}, strings.NewReader(""), &stdout, &stderr, cliServices{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	results := decodeResults(t, &stdout)
	if len(results) != 2 {
		t.Fatalf("results=%+v", results)
	}
	for _, result := range results {
		if result.Error != "" {
			t.Fatalf("pacing consumed deadline: %+v", result)
		}
	}
}

func TestScheduledFreshAddressPrecedesRetry(t *testing.T) {
	var mu sync.Mutex
	var questions []string
	server := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		questions = append(questions, q.Question[0].Name)
		mu.Unlock()
		if strings.HasPrefix(q.Question[0].Name, "0.") {
			reply := new(dns.Msg).SetReply(q)
			reply.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(reply)
			return
		}
		ptrReply(w, q)
	})
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"-d", server, "-c", "1", "-r", "2", "192.0.2.0/31"}, strings.NewReader(""), &stdout, &stderr, cliServices{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(questions) != 4 || !strings.HasPrefix(questions[1], "1.") {
		t.Fatalf("fresh address blocked by retries: %v", questions)
	}
	if len(decodeResults(t, &stdout)) != 2 {
		t.Fatalf("incomplete results: %s", &stdout)
	}
}

func TestTargetIteratorLastIPv4AndLargePrefix(t *testing.T) {
	it := targetIterator{targets: []target{{label: "last", prefix: netip.MustParsePrefix("255.255.255.254/31")}, {label: "large", prefix: netip.MustParsePrefix("0.0.0.0/0")}}}
	for i, want := range []string{"255.255.255.254", "255.255.255.255", "0.0.0.0", "0.0.0.1"} {
		got, target, ok := it.next()
		if !ok || got.String() != want || (i < 2 && target.label != "last") || (i >= 2 && target.label != "large") {
			t.Fatalf("step %d: %v %v %v", i, got, target, ok)
		}
	}
}

func TestRateValidation(t *testing.T) {
	for _, flag := range []string{"--rate=-1", "--resolver-rate=-1", "--rate=1000000001"} {
		var stderr bytes.Buffer
		if code := runCLI(context.Background(), []string{flag, "192.0.2.1"}, strings.NewReader(""), &bytes.Buffer{}, &stderr, cliServices{}); code != 2 {
			t.Fatalf("%s: code %d: %s", flag, code, &stderr)
		}
	}
}

func TestSystemNameserverFallbackSharesBudget(t *testing.T) {
	first := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg).SetReply(q)
		reply.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(reply)
	})
	second := localDNS(t, ptrReply)
	services := cliServices{resolvers: func(_ []string, timeout time.Duration) ([]*dnsResolver, error) {
		return []*dnsResolver{newDNSResolver("system", []string{first, second}, timeout)}, nil
	}}
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := runCLI(context.Background(), []string{"--rate", "10", "-t", "1s", "-r", "0", "192.0.2.1"}, strings.NewReader(""), &stdout, &stderr, services)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	results := decodeResults(t, &stdout)
	if len(results) != 1 || results[0].Error != "" {
		t.Fatalf("results=%+v", results)
	}
	if time.Since(start) < 95*time.Millisecond {
		t.Fatal("system fallback bypassed send budget")
	}
}

func TestCancelDuringTCPPacing(t *testing.T) {
	received := make(chan struct{}, 1)
	server := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg).SetReply(q)
		reply.Truncated = true
		_ = w.WriteMsg(reply)
		select {
		case received <- struct{}{}:
		default:
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{"-d", server, "--rate", "1", "-t", "10s", "192.0.2.1"}, strings.NewReader(""), &stdout, &stderr, cliServices{})
	}()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("initial query missing")
	}
	cancel()
	select {
	case code := <-done:
		if code != 1 || stdout.Len() != 0 {
			t.Fatalf("canceled run: code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pacing cancellation did not drain")
	}
}
