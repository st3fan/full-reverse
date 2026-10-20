package main

import (
	"context"
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const maxPendingDNS = 1024
const dnsIDCount = 1 << 16

type dnsReply struct {
	msg *dns.Msg
	err error
}

type pendingDNS struct {
	question dns.Question
	opcode   int
	reply    chan dnsReply
}

type udpSession struct {
	conn    *net.UDPConn
	peer    netip.AddrPort
	ids     []uint16
	next    int
	pending map[uint16]*pendingDNS // guarded by transport.mu
	err     error                  // guarded by transport.mu
	writes  chan struct{}          // serializes write deadlines, without blocking cancellation
	done    chan struct{}
}

// Share history across every endpoint in one engine run. Different configured
// names can resolve to the same peer, so per-name histories are insufficient.
type udpPortHistory struct {
	mu   sync.Mutex
	bits [dnsIDCount / 64]uint64
}

func (h *udpPortHistory) claim(port uint16) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	bit := uint64(1) << (port % 64)
	if h.bits[port/64]&bit != 0 {
		return false
	}
	h.bits[port/64] |= bit
	return true
}

// udpTransport owns one live UDP socket per endpoint (two briefly during
// rotation). IDs are randomly permuted and used once per socket, including
// timed-out and canceled attempts. Socket rotation waits for pending queries to
// drain. Shared fixed-size history prevents local-port reuse during the run,
// so even an arbitrarily late reply to an identical question cannot match
// a new query after ID-space rotation. Port exhaustion fails visibly.
type udpTransport struct {
	server    string
	ctx       context.Context
	cancel    context.CancelFunc
	slots     chan struct{}
	mu        sync.Mutex
	session   *udpSession
	ports     *udpPortHistory
	idCount   int // production: full ID space; smaller values allow exhaustion tests
	changed   chan struct{}
	closed    bool
	receivers sync.WaitGroup
}

func newUDPTransport(server string) *udpTransport {
	return newUDPTransportWithPorts(server, &udpPortHistory{})
}

func newUDPTransportWithPorts(server string, ports *udpPortHistory) *udpTransport {
	if ports == nil {
		ports = &udpPortHistory{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &udpTransport{server: server, ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, maxPendingDNS), ports: ports, idCount: dnsIDCount, changed: make(chan struct{})}
}

// notifyLocked wakes ID-space waiters whenever pending work or socket state changes.
func (t *udpTransport) notifyLocked() { close(t.changed); t.changed = make(chan struct{}) }

func (t *udpTransport) openLocked(ctx context.Context) (*udpSession, error) {
	// The kernel chooses ephemeral ports. Reject previously used ones, holding
	// the previous live socket open while choosing the replacement.
	for range 64 {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", t.server)
		if err != nil {
			return nil, err
		}
		udp := conn.(*net.UDPConn)
		port := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
		if !t.ports.claim(port) {
			_ = udp.Close()
			continue
		}
		if err := udp.SetReadBuffer(4 << 20); err != nil {
			_ = udp.Close()
			return nil, err
		}
		var seed [32]byte
		if _, err := rand.Read(seed[:]); err != nil {
			_ = udp.Close()
			return nil, err
		}
		ids := make([]uint16, dnsIDCount)
		for i := range ids {
			ids[i] = uint16(i)
		}
		rng := mathrand.New(mathrand.NewChaCha8(seed))
		rng.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
		return &udpSession{conn: udp, peer: udp.RemoteAddr().(*net.UDPAddr).AddrPort(),
			ids: ids[:t.idCount], pending: make(map[uint16]*pendingDNS), writes: make(chan struct{}, 1), done: make(chan struct{})}, nil
	}
	return nil, fmt.Errorf("cannot allocate an unused UDP source port for %s", t.server)
}

func (t *udpTransport) reserve(ctx context.Context, q *dns.Msg) (*udpSession, uint16, *pendingDNS, error) {
	for {
		t.mu.Lock()
		if err := ctx.Err(); err != nil {
			t.mu.Unlock()
			return nil, 0, nil, err
		}
		if t.closed {
			t.mu.Unlock()
			return nil, 0, nil, net.ErrClosed
		}
		s := t.session
		if s == nil || s.err != nil || (s.next == len(s.ids) && len(s.pending) == 0) {
			next, err := t.openLocked(ctx)
			if err != nil {
				t.mu.Unlock()
				return nil, 0, nil, err
			}
			t.session = next
			t.receivers.Add(1)
			go t.receive(next)
			if s != nil {
				s.ids = nil // Retired sessions need no allocation history.
				_ = s.conn.Close()
			}
			t.notifyLocked()
			t.mu.Unlock()
			if s != nil {
				<-s.done
			}
			continue
		}
		if s.next == len(s.ids) {
			changed := t.changed
			t.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, 0, nil, ctx.Err()
			case <-changed:
			}
			continue
		}
		id := s.ids[s.next]
		s.next++
		pending := &pendingDNS{question: q.Question[0], opcode: q.Opcode, reply: make(chan dnsReply, 1)}
		s.pending[id] = pending
		t.mu.Unlock()
		return s, id, pending, nil
	}
}

func (t *udpTransport) exchange(parent context.Context, q *dns.Msg) (*dns.Msg, error) {
	if len(q.Question) != 1 {
		return nil, fmt.Errorf("DNS transport requires one question")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	select {
	case t.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-t.slots }()
	s, id, pending, err := t.reserve(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() {
		t.mu.Lock()
		delete(s.pending, id)
		if len(s.pending) == 0 {
			t.notifyLocked()
		}
		t.mu.Unlock()
	}()
	msg := q.Copy()
	msg.Id = id
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	select {
	case s.writes <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err = ctx.Err(); err == nil {
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(2 * time.Second)
		}
		err = s.conn.SetWriteDeadline(deadline)
		if err == nil {
			_, err = s.conn.Write(wire)
		}
	}
	<-s.writes
	if err != nil {
		return nil, err
	}
	select {
	case result := <-pending.reply:
		return result.msg, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func validDNSReply(question dns.Question, opcode int, response *dns.Msg) bool {
	return response.Response && !response.Zero && response.Opcode == opcode && len(response.Question) == 1 &&
		equalDNSName(response.Question[0].Name, question.Name) &&
		response.Question[0].Qtype == question.Qtype && response.Question[0].Qclass == question.Qclass
}

// DNS case insensitivity applies to ASCII A-Z, not Unicode case folding.
func equalDNSName(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func (t *udpTransport) accept(s *udpSession, peer netip.AddrPort, response *dns.Msg) {
	if peer.Addr().Unmap() != s.peer.Addr().Unmap() || peer.Port() != s.peer.Port() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p := s.pending[response.Id]
	if p == nil || !validDNSReply(p.question, p.opcode, response) {
		return
	}
	delete(s.pending, response.Id)
	p.reply <- dnsReply{msg: response}
	if len(s.pending) == 0 {
		t.notifyLocked()
	}
}

func (t *udpTransport) receive(s *udpSession) {
	defer t.receivers.Done()
	defer close(s.done)
	packet := make([]byte, 65535)
	for {
		n, peer, err := s.conn.ReadFromUDPAddrPort(packet)
		if err != nil {
			t.mu.Lock()
			if t.session == s && !t.closed {
				s.err = fmt.Errorf("receive DNS from %s: %w", t.server, err)
				for id, p := range s.pending {
					delete(s.pending, id)
					p.reply <- dnsReply{err: s.err}
				}
				t.notifyLocked()
			}
			t.mu.Unlock()
			return
		}
		response := new(dns.Msg)
		if err := response.Unpack(packet[:n]); err == nil {
			t.accept(s, peer, response)
		}
	}
}

func (t *udpTransport) close() {
	t.cancel() // Interrupt a dial or ID-space waiter before taking the mutex.
	t.mu.Lock()
	t.closed = true
	if t.session != nil {
		_ = t.session.conn.Close()
	}
	t.notifyLocked()
	t.mu.Unlock()
	t.receivers.Wait()
}
