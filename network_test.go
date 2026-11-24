package permuteproxy

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFuncsUnsupported(t *testing.T) {
	ctx := context.Background()
	var n Network = NetworkFuncs{}
	var tr Transport = TransportFuncs{Plane: Stream}
	for name, err := range map[string]error{
		"net dial":         func() error { _, err := n.DialContext(ctx, "tcp", "x"); return err }(),
		"net listen":       func() error { _, err := n.Listen(ctx, "tcp", "x"); return err }(),
		"net listenpacket": func() error { _, err := n.ListenPacket(ctx, "udp", "x"); return err }(),
		"transport dial":   func() error { _, err := tr.Dial(ctx, Stream); return err }(),
		"transport listen": func() error { _, err := tr.Listen(ctx); return err }(),
	} {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want ErrUnsupported", name, err)
		}
	}
}

// datagramPeer listens on an ephemeral address of network, a temp path for unixgram.
func datagramPeer(t *testing.T, network string) net.PacketConn {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "unixgram" {
		if runtime.GOOS == "windows" {
			t.Skip("unixgram needs a POSIX system")
		}
		address = filepath.Join(t.TempDir(), "p")
	}
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

// exchange proves conn is an unconnected datagram socket bound to target: Write reaches target,
// WriteTo reaches a second peer and that peer's reply arrives through ReadFrom with its address.
func exchange(t *testing.T, conn net.Conn, target net.PacketConn) {
	t.Helper()
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("conn is not a net.PacketConn")
	}
	if conn.RemoteAddr().String() != target.LocalAddr().String() {
		t.Fatalf("RemoteAddr() = %v, want %v", conn.RemoteAddr(), target.LocalAddr())
	}
	other := datagramPeer(t, target.LocalAddr().Network())
	buf := make([]byte, 16)
	for _, step := range []struct {
		to   net.Addr
		peer net.PacketConn
	}{{nil, target}, {other.LocalAddr(), other}} {
		var err error
		if step.to == nil {
			_, err = conn.Write([]byte("ping"))
		} else {
			_, err = pc.WriteTo([]byte("ping"), step.to)
		}
		if err != nil {
			t.Fatal(err)
		}
		step.peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := step.peer.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("peer read %q, %v", buf[:n], err)
		}
		if _, err := step.peer.WriteTo([]byte("pong"), from); err != nil {
			t.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err = pc.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "pong" || from.String() != step.peer.LocalAddr().String() {
			t.Fatalf("ReadFrom = %q from %v, %v; want \"pong\" from %v", buf[:n], from, err, step.peer.LocalAddr())
		}
	}
}

// hasty is a udp socket whose read deadline falls due as soon as one is set.
type hasty struct{ *net.UDPConn }

func (h hasty) SetReadDeadline(time.Time) error { return h.UDPConn.SetReadDeadline(time.Now()) }

// misdirected is a hasty conn to remote whose datagrams leave through out, or nowhere without one.
type misdirected struct {
	hasty
	out    net.PacketConn
	remote net.Addr
}

func (m misdirected) RemoteAddr() net.Addr { return m.remote }

func (m misdirected) Write(b []byte) (int, error) { return m.WriteTo(b, m.remote) }

func (m misdirected) WriteTo(b []byte, addr net.Addr) (int, error) {
	if m.out == nil {
		return len(b), nil
	}
	return m.out.WriteTo(b, addr)
}

func TestExchangeFailsOnALostDatagram(t *testing.T) {
	if lost := os.Getenv("PERMUTEPROXY_LOST_DATAGRAM"); lost != "" {
		// The child: exchange over a conn whose ping or pong never arrives.
		target := datagramPeer(t, "udp").(*net.UDPConn)
		conn := misdirected{hasty: hasty{datagramPeer(t, "udp").(*net.UDPConn)}, remote: target.LocalAddr()}
		var peer net.PacketConn = hasty{target}
		if lost == "pong" {
			conn.out, peer = datagramPeer(t, "udp"), target
		}
		exchange(t, conn, peer)
		return
	}
	for _, lost := range []string{"ping", "pong"} {
		child := exec.Command(os.Args[0], "-test.run=^TestExchangeFailsOnALostDatagram$", "-test.timeout=10s")
		child.Env = append(os.Environ(), "PERMUTEPROXY_LOST_DATAGRAM="+lost)
		out, err := child.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "i/o timeout") {
			t.Errorf("exchange over a lost %s ended with %v, want its test failed on a read timeout:\n%s", lost, err, out)
		}
	}
}

// closedPacket closes conn and checks a unixgram conn's private socket directory is gone.
func closedPacket(t *testing.T, conn net.Conn) {
	t.Helper()
	local := conn.LocalAddr()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if local.Network() != "unixgram" {
		return
	}
	if _, err := os.Stat(filepath.Dir(local.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private directory of %v survived Close: %v", local, err)
	}
}

func TestViewsForwardLossy(t *testing.T) {
	lossy := &lossyNet{fakeNet{name: "lossy"}, []string{"udp"}}
	for name, view := range map[string]Network{
		"borrowed":   borrowed{lossy},
		"restricted": restricted{network: lossy, plane: Stream | Packet},
	} {
		l, ok := view.(LossyNetwork)
		if !ok {
			t.Fatalf("%s view is not a LossyNetwork", name)
		}
		if !l.Lossy("udp") || l.Lossy("unixgram") {
			t.Fatalf("%s view: Lossy(udp) = %v, Lossy(unixgram) = %v; want what its network reports", name, l.Lossy("udp"), l.Lossy("unixgram"))
		}
	}
	for name, view := range map[string]Network{
		"borrowed":   borrowed{&fakeNet{name: "plain"}},
		"restricted": restricted{network: &fakeNet{name: "plain"}, plane: Stream | Packet},
	} {
		if l, ok := view.(LossyNetwork); !ok || l.Lossy("udp") {
			t.Fatalf("%s view of a network without Lossy reports udp lossy", name)
		}
	}
}
