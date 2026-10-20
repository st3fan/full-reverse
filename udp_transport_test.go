package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type wireDNS struct {
	query *dns.Msg
	peer  netip.AddrPort
}

type rawDNSFixture struct {
	conn     *net.UDPConn
	requests chan wireDNS
	done     chan struct{}
}

func rawDNS(t *testing.T, network, address string) *rawDNSFixture {
	t.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		if network == "udp6" {
			t.Skipf("IPv6 unavailable: %v", err)
		}
		t.Fatal(err)
	}
	f := &rawDNSFixture{conn: conn, requests: make(chan wireDNS, 128), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		buf := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if err := q.Unpack(buf[:n]); err != nil {
				t.Errorf("decode request: %v", err)
				return
			}
			select {
			case f.requests <- wireDNS{q, peer}:
			case <-time.After(2 * time.Second):
				t.Error("fixture request queue blocked")
				return
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-f.done })
	return f
}

func (f *rawDNSFixture) request(t *testing.T) wireDNS {
	t.Helper()
	select {
	case q := <-f.requests:
		return q
	case <-time.After(2 * time.Second):
		t.Fatal("DNS request not sent")
		return wireDNS{}
	}
}

func (f *rawDNSFixture) reply(t *testing.T, q wireDNS, m *dns.Msg) {
	t.Helper()
	if m == nil {
		m = new(dns.Msg).SetReply(q.query)
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.conn.WriteToUDPAddrPort(wire, q.peer); err != nil {
		t.Fatal(err)
	}
}

func testUDPTransport(t *testing.T, f *rawDNSFixture) *udpTransport {
	t.Helper()
	tr := newUDPTransport(f.conn.LocalAddr().String())
	t.Cleanup(tr.close)
	return tr
}

func asyncExchange(ctx context.Context, tr *udpTransport, name string) <-chan dnsReply {
	done := make(chan dnsReply, 1)
	go func() {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypePTR)
		m, err := tr.exchange(ctx, q)
		done <- dnsReply{m, err}
	}()
	return done
}

func awaitDNS(t *testing.T, done <-chan dnsReply) dnsReply {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("DNS exchange did not complete")
		return dnsReply{}
	}
}

func assertNoDNS(t *testing.T, done <-chan dnsReply) {
	t.Helper()
	select {
	case r := <-done:
		t.Fatalf("unexpected DNS completion: %+v", r)
	case <-time.After(10 * time.Millisecond):
	}
}

func TestUDPTransportMultiplexing(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	const count = 32
	done := make([]<-chan dnsReply, count)
	for i := range count {
		done[i] = asyncExchange(ctx, tr, fmt.Sprintf("%d.2.0.192.in-addr.arpa.", i))
	}
	requests := make([]wireDNS, count)
	ids := map[uint16]bool{}
	for i := range count {
		q := f.request(t)
		requests[i] = q
		if ids[q.query.Id] {
			t.Fatal("reused outstanding ID")
		}
		ids[q.query.Id] = true
		if q.peer != requests[0].peer {
			t.Fatal("queries did not share a socket")
		}
	}
	for i := count - 1; i >= 0; i-- {
		f.reply(t, requests[i], nil)
		f.reply(t, requests[i], nil)
	}
	for i, d := range done {
		r := awaitDNS(t, d)
		if r.err != nil || r.msg.Question[0].Name != fmt.Sprintf("%d.2.0.192.in-addr.arpa.", i) {
			t.Fatalf("mismatched reply: %+v", r)
		}
	}
}

func TestUDPTransportValidation(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	for _, kind := range []string{"id", "name", "type", "class", "opcode", "qr", "reserved", "source-port", "source-address", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
			q := f.request(t)
			m := new(dns.Msg).SetReply(q.query)
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
			}
			if strings.HasPrefix(kind, "source-") {
				tr.mu.Lock()
				s := tr.session
				tr.mu.Unlock()
				peer := s.peer
				if kind == "source-port" {
					peer = netip.AddrPortFrom(peer.Addr(), peer.Port()+1)
				} else {
					peer = netip.MustParseAddrPort("127.0.0.2:53")
				}
				tr.accept(s, peer, m)
			} else if kind == "malformed" {
				if _, err := f.conn.WriteToUDPAddrPort([]byte{1, 2, 3}, q.peer); err != nil {
					t.Fatal(err)
				}
			} else {
				f.reply(t, q, m)
			}
			assertNoDNS(t, done)
			valid := new(dns.Msg).SetReply(q.query)
			valid.Question[0].Name = strings.ToUpper(valid.Question[0].Name)
			f.reply(t, q, valid)
			if r := awaitDNS(t, done); r.err != nil {
				t.Fatal(r.err)
			}
		})
	}
}

func TestUDPTransportLateIdenticalQuestions(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	first := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	old := f.request(t)
	cancel()
	if r := awaitDNS(t, first); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("cancel: %v", r.err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	second := asyncExchange(ctx2, tr, "1.2.0.192.in-addr.arpa.")
	current := f.request(t)
	if old.query.Id == current.query.Id || old.peer != current.peer {
		t.Fatal("expected a new ID on the same socket")
	}
	f.reply(t, old, nil)
	assertNoDNS(t, second)
	f.reply(t, current, nil)
	if r := awaitDNS(t, second); r.err != nil {
		t.Fatal(r.err)
	}
	third := asyncExchange(ctx2, tr, "1.2.0.192.in-addr.arpa.")
	next := f.request(t)
	f.reply(t, current, nil)
	assertNoDNS(t, third)
	f.reply(t, next, nil)
	if r := awaitDNS(t, third); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestUDPTransportDeadlineRetiresID(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	old := f.request(t)
	if r := awaitDNS(t, done); !errors.Is(r.err, context.DeadlineExceeded) {
		t.Fatalf("deadline result: %v", r.err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	next := asyncExchange(ctx2, tr, "1.2.0.192.in-addr.arpa.")
	q := f.request(t)
	if old.query.Id == q.query.Id {
		t.Fatal("timed-out ID was reused")
	}
	f.reply(t, old, nil)
	assertNoDNS(t, next)
	f.reply(t, q, nil)
	if r := awaitDNS(t, next); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestUDPTransportIDExhaustionAndRotation(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	tr.idCount = 2
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	q1 := f.request(t)
	second := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	q2 := f.request(t)
	waitCtx, stop := context.WithCancel(ctx)
	waiter := asyncExchange(waitCtx, tr, "1.2.0.192.in-addr.arpa.")
	assertNoDNS(t, waiter)
	stop()
	if r := awaitDNS(t, waiter); !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	third := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	f.reply(t, q1, nil)
	if r := awaitDNS(t, first); r.err != nil {
		t.Fatal(r.err)
	}
	select {
	case <-f.requests:
		t.Fatal("rotated with pending queries")
	case <-time.After(10 * time.Millisecond):
	}
	f.reply(t, q2, nil)
	if r := awaitDNS(t, second); r.err != nil {
		t.Fatal(r.err)
	}
	q3 := f.request(t)
	if q3.peer == q1.peer {
		t.Fatal("source port reused after ID exhaustion")
	}
	f.reply(t, q1, nil)
	f.reply(t, q2, nil)
	assertNoDNS(t, third)
	f.reply(t, q3, nil)
	if r := awaitDNS(t, third); r.err != nil {
		t.Fatal(r.err)
	}
	ports := map[uint16]bool{q1.peer.Port(): true, q3.peer.Port(): true}
	for range 8 {
		done := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
		q := f.request(t)
		// Sessions have two IDs. A new port may appear, but a retired port may not.
		tr.mu.Lock()
		s := tr.session
		tr.mu.Unlock()
		if s.next == 1 {
			if ports[q.peer.Port()] {
				t.Fatal("retired source port reused")
			}
			ports[q.peer.Port()] = true
		}
		f.reply(t, q, nil)
		if r := awaitDNS(t, done); r.err != nil {
			t.Fatal(r.err)
		}
	}
}

func TestUDPTransportCapacityAndShutdown(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	tr.slots = make(chan struct{}, 1)
	first := asyncExchange(context.Background(), tr, "1.2.0.192.in-addr.arpa.")
	f.request(t)
	ctx, cancel := context.WithCancel(context.Background())
	second := asyncExchange(ctx, tr, "2.2.0.192.in-addr.arpa.")
	assertNoDNS(t, second)
	cancel()
	if r := awaitDNS(t, second); !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	select {
	case <-f.requests:
		t.Fatal("capacity bound exceeded")
	default:
	}
	tr.close()
	if r := awaitDNS(t, first); r.err == nil {
		t.Fatal("shutdown did not fail pending query")
	}
	tr.mu.Lock()
	s := tr.session
	pending := len(s.pending)
	tr.mu.Unlock()
	if pending != 0 || len(tr.slots) != 0 {
		t.Fatal("pending work leaked after shutdown")
	}
	select {
	case <-s.done:
	default:
		t.Fatal("receiver not joined")
	}
}

func TestUDPTransportReceiveFailureRecovery(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	old := f.request(t)
	tr.mu.Lock()
	s := tr.session
	tr.mu.Unlock()
	_ = s.conn.Close()
	if r := awaitDNS(t, done); r.err == nil {
		t.Fatal("receive failure was hidden")
	}
	next := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	q := f.request(t)
	if q.peer == old.peer {
		t.Fatal("failed socket port reused")
	}
	f.reply(t, q, nil)
	if r := awaitDNS(t, next); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestUDPTransportPortExhaustion(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	for i := range tr.ports {
		tr.ports[i] = ^uint64(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("1.2.0.192.in-addr.arpa.", dns.TypePTR)
	if _, err := tr.exchange(ctx, q); err == nil || !strings.Contains(err.Error(), "unused UDP source port") {
		t.Fatalf("port exhaustion: %v", err)
	}
}

func TestUDPTransportIPv6(t *testing.T) {
	f := rawDNS(t, "udp6", "[::1]:0")
	tr := testUDPTransport(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := asyncExchange(ctx, tr, "1.2.0.192.in-addr.arpa.")
	q := f.request(t)
	f.reply(t, q, nil)
	if r := awaitDNS(t, done); r.err != nil {
		t.Fatal(r.err)
	}
}

func TestUDPTransportConcurrentClose(t *testing.T) {
	f := rawDNS(t, "udp4", "127.0.0.1:0")
	tr := testUDPTransport(t, f)
	done := asyncExchange(context.Background(), tr, "1.2.0.192.in-addr.arpa.")
	f.request(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); tr.close() }()
	}
	wg.Wait()
	if r := awaitDNS(t, done); r.err == nil {
		t.Fatal("query succeeded after close")
	}
}
