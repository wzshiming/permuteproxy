package quic_test

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
)

// memNet is an in-memory datagram network for the udp and unixgram carriers of a TransportEngine.
type memNet struct {
	permuteproxy.NetworkFuncs
	loss, reorder       float64 // shares of datagrams dropped, and of those held back behind the next one to the same peer
	failRead, failWrite error   // when set, what every ReadFrom or WriteTo returns

	mu        sync.Mutex
	rng       *rand.Rand
	port      int
	sockets   map[string]*memSocket // bound, by address
	bound     []*memSocket          // every socket ever bound, in order
	held      map[string]datagram   // by destination
	dropped   int
	reordered int
	sent      chan struct{} // closed on the first datagram written
	once      sync.Once
}

type datagram struct {
	b    []byte
	from net.Addr
}

func newMemNet() *memNet {
	return &memNet{
		rng:     rand.New(rand.NewPCG(1, 2)),
		port:    40000,
		sockets: map[string]*memSocket{},
		held:    map[string]datagram{},
		sent:    make(chan struct{}),
	}
}

// key is where addr is bound in the network.
func key(addr net.Addr) string {
	if a, ok := addr.(*net.UDPAddr); ok {
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return addr.String()
}

func (m *memNet) ListenPacket(_ context.Context, network, address string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var local net.Addr = &net.UnixAddr{Name: address, Net: network}
	if network != "unixgram" {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if host == "" {
			host = "127.0.0.1"
		}
		if port == "0" {
			m.port++
			port = strconv.Itoa(m.port)
		}
		ap, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
		if err != nil {
			return nil, err
		}
		local = net.UDPAddrFromAddrPort(ap)
	}
	if _, ok := m.sockets[key(local)]; ok {
		return nil, errors.New("address in use")
	}
	s := &memSocket{net: m, local: local, in: make(chan datagram, 4096), done: make(chan struct{})}
	m.sockets[key(local)] = s
	m.bound = append(m.bound, s)
	return s, nil
}

// socket is the i-th socket m bound.
func (m *memNet) socket(t *testing.T, i int) *memSocket {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.bound) {
		t.Fatalf("socket %d of %d bound", i, len(m.bound))
	}
	return m.bound[i]
}

// cut loses every datagram from now on.
func (m *memNet) cut() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loss = 1
}

func (m *memNet) send(d datagram, to string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.once.Do(func() { close(m.sent) })
	if m.rng.Float64() < m.loss {
		m.dropped++
		return
	}
	if held, ok := m.held[to]; ok {
		delete(m.held, to)
		m.deliver(d, to)
		m.deliver(held, to)
		return
	}
	if m.rng.Float64() < m.reorder {
		m.reordered++
		m.held[to] = d
		return
	}
	m.deliver(d, to)
}

// impaired reports how many datagrams m has dropped and reordered.
func (m *memNet) impaired() (dropped, reordered int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped, m.reordered
}

func (m *memNet) deliver(d datagram, to string) {
	if s, ok := m.sockets[to]; ok {
		select {
		case s.in <- d:
		default:
		}
	}
}

// memSocket is a socket of a memNet; it counts its writes, its Close calls and the calls in flight.
type memSocket struct {
	net    *memNet
	local  net.Addr
	in     chan datagram
	done   chan struct{}
	once   sync.Once
	writes atomic.Int32
	closes atomic.Int32
	active atomic.Int32
}

func (s *memSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	if err := s.net.failRead; err != nil {
		return 0, nil, err
	}
	select {
	case d := <-s.in:
		return copy(b, d.b), d.from, nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}

func (s *memSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	s.writes.Add(1)
	if err := s.net.failWrite; err != nil {
		return 0, err
	}
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	s.net.send(datagram{b: bytes.Clone(b), from: s.local}, key(addr))
	return len(b), nil
}

func (s *memSocket) Close() error {
	s.closes.Add(1)
	s.once.Do(func() {
		close(s.done)
		s.net.mu.Lock()
		delete(s.net.sockets, key(s.local))
		s.net.mu.Unlock()
	})
	return nil
}

func (s *memSocket) LocalAddr() net.Addr                { return s.local }
func (s *memSocket) SetDeadline(t time.Time) error      { return nil }
func (s *memSocket) SetReadDeadline(t time.Time) error  { return nil }
func (s *memSocket) SetWriteDeadline(t time.Time) error { return nil }

// overCarriers runs f over a real udp loopback, an in-memory network and one that loses and reorders datagrams.
func overCarriers(t *testing.T, f func(t *testing.T, e permuteproxy.TransportEngine)) {
	lossy := newMemNet()
	lossy.loss, lossy.reorder = 0.05, 0.1
	for _, c := range []struct {
		name string
		e    permuteproxy.TransportEngine
	}{
		{"udp", permuteproxy.TransportEngine{}},
		{"memory", permuteproxy.TransportEngine{Base: newMemNet()}},
		{"lossy", permuteproxy.TransportEngine{Base: lossy}},
	} {
		t.Run(c.name, func(t *testing.T) { f(t, c.e) })
	}
}
