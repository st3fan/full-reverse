package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolverRejectsInvalidTCP(t *testing.T) {
	for _, kind := range []string{"id", "name", "type", "class", "opcode", "qr", "reserved", "missing-question", "truncated", "valid"} {
		t.Run(kind, func(t *testing.T) {
			addr := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg).SetReply(q)
				if w.LocalAddr().Network() == "udp" {
					m.Truncated = true
				} else {
					switch kind {
					case "id":
						m.Id++
					case "name":
						m.Question[0].Name = "other.example."
					case "type":
						m.Question[0].Qtype = dns.TypeA
					case "class":
						m.Question[0].Qclass = dns.ClassCHAOS
					case "opcode":
						m.Opcode = dns.OpcodeStatus
					case "qr":
						m.Response = false
					case "reserved":
						m.Zero = true
					case "missing-question":
						m.Question = nil
					case "truncated":
						m.Truncated = true
					}
				}
				_ = w.WriteMsg(m)
			})
			dr := newDNSResolver("fixture", []string{addr}, time.Second)
			defer dr.close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := dr.query(ctx, "1.2.0.192.in-addr.arpa.", dns.TypePTR)
			if (err == nil) != (kind == "valid") {
				t.Fatalf("TCP %s: %v", kind, err)
			}
		})
	}
}

func TestResolverTCPBackpressureCancellation(t *testing.T) {
	var tcpCalls atomic.Int64
	started := make(chan struct{})
	secondUDP := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	addr := localDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if w.LocalAddr().Network() == "udp" {
			if q.Question[0].Name == "2.2.0.192.in-addr.arpa." {
				close(secondUDP)
			}
			m := new(dns.Msg).SetReply(q)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		tcpCalls.Add(1)
		once.Do(func() { close(started) })
		<-release
	})
	defer close(release)
	dr := newDNSResolver("fixture", []string{addr}, time.Minute)
	defer dr.close()
	dr.tcpSlots = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := dr.query(ctx, "1.2.0.192.in-addr.arpa.", dns.TypePTR); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP fallback did not start")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { _, err := dr.query(ctx2, "2.2.0.192.in-addr.arpa.", dns.TypePTR); done2 <- err }()
	select {
	case <-secondUDP:
	case <-time.After(2 * time.Second):
		t.Fatal("second UDP query did not start")
	}
	cancel2()
	select {
	case err := <-done2:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP gate did not cancel")
	}
	if tcpCalls.Load() != 1 {
		t.Fatal("TCP capacity exceeded")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP read did not cancel")
	}
	if len(dr.tcpSlots) != 0 {
		t.Fatal("TCP slot leaked")
	}
}

func TestEngineClosesPersistentSockets(t *testing.T) {
	addr := localDNS(t, ptrReply)
	for _, inputs := range [][]string{{"192.0.2.0/28"}, {"2001:db8::1"}} {
		var resolver *dnsResolver
		services := cliServices{resolvers: func(_ []string, timeout time.Duration) ([]*dnsResolver, error) {
			resolver = newDNSResolver("fixture", []string{addr}, timeout)
			return []*dnsResolver{resolver}, nil
		}}
		err := runLookups(context.Background(), lookupOptions{concurrency: 4, timeout: time.Second, quiet: true}, inputs, io.Discard, io.Discard, services)
		if (err == nil) != (inputs[0] == "192.0.2.0/28") {
			t.Fatal(err)
		}
		resolver.mu.Lock()
		closed := resolver.closed
		transports := resolver.transports
		resolver.mu.Unlock()
		if !closed {
			t.Fatal("resolver not closed")
		}
		for _, transport := range transports {
			transport.mu.Lock()
			s := transport.session
			pending := len(s.pending)
			transport.mu.Unlock()
			if pending != 0 || len(transport.slots) != 0 {
				t.Fatal("pending transport state leaked")
			}
			select {
			case <-s.done:
			default:
				t.Fatal("receiver not joined")
			}
		}
	}
}
