package sshproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// framedBinds counts the sockets test-ssh-framed binds through its local network.
var framedBinds atomic.Int32

func init() {
	// test-ssh-framed stands in for a proxy whose datagrams need boundaries, as socks5's do.
	permuteproxy.RegisterLayer("test-ssh-framed", permuteproxy.Spec{
		Kind:     permuteproxy.KindProxy,
		Requires: permuteproxy.Stream,
		Provides: permuteproxy.Stream | permuteproxy.Packet,
		Networks: []string{"tcp", "udp"},
		NewClient: func(permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
			return &permuteproxy.ClientFuncs{
				Dial: func(ctx context.Context, inner permuteproxy.Transport, _, _ string) (net.Conn, error) {
					return inner.Dial(ctx, permuteproxy.Stream)
				},
				ListenPacket: func(ctx context.Context, _ permuteproxy.Transport, local permuteproxy.Network, network, address string) (net.PacketConn, error) {
					framedBinds.Add(1)
					return local.ListenPacket(ctx, network, address)
				},
			}, nil
		},
	})
}

func TestUDPDialRoundTripsThroughExec(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	conn, err := n.DialContext(timeout(t), "udp", "198.51.100.7:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "nc -u -w 30 198.51.100.7 53|ping")
	if got, want := recv(t, up.commands, "the command").line, "nc -u -w 30 198.51.100.7 53"; got != want {
		t.Fatalf("server ran %q, want %q", got, want)
	}
}

func TestUDPListenPacketTagsEachPeer(t *testing.T) {
	n := dialServer(t, &clientBase{}, serveExec(t, newUpstream()), withCredentials())
	pc, err := n.ListenPacket(timeout(t), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// A name reaches the server unresolved.
	for _, peer := range []net.Addr{&net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53}, netutils.NewNetAddr("udp", "peer.invalid:5353")} {
		if _, err := pc.WriteTo([]byte("hi"), peer); err != nil {
			t.Fatal(err)
		}
	}
	pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := map[string]string{}
	buf := make([]byte, 256)
	for range 2 {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		got[from.String()] = string(buf[:n])
	}
	want := map[string]string{
		"198.51.100.1:53":   "nc -u -w 30 198.51.100.1 53|hi",
		"peer.invalid:5353": "nc -u -w 30 peer.invalid 5353|hi",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("datagrams by peer mismatch (-want +got):\n%s", diff)
	}
}

func TestUDPConcurrentWritesToOnePeerArriveWhole(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials("udp_command", "record %h %p"))
	pc, err := n.ListenPacket(timeout(t), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// The first write opens the session the others share.
	peer := netutils.NewNetAddr("udp", "198.51.100.7:53")
	if _, err := pc.WriteTo([]byte("open"), peer); err != nil {
		t.Fatal(err)
	}
	cmd := recv(t, up.commands, "the command")
	var wg sync.WaitGroup
	for i := range 52 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc.WriteTo(bytes.Repeat([]byte{'a' + byte(i%26)}, 1024), peer)
		}()
	}
	wg.Wait()
	var got strings.Builder
	for got.Len() < len("open")+52*1024 {
		got.Write(recv(t, cmd.input, "the writes to arrive"))
	}
	for i := range 26 {
		if run := strings.Repeat(string(rune('a'+i)), 1024); strings.Count(got.String(), run) != 2 {
			t.Fatalf("writes of %q did not arrive whole", run[:1])
		}
	}
}

func TestUDPWriteEndsAtDeadlineOrCloseWhileExecWaits(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials("udp_command", "stall %h %p"))
	pc, err := n.ListenPacket(timeout(t), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	write := func(peer string) <-chan error {
		written := make(chan error, 1)
		go func() {
			_, err := pc.WriteTo([]byte("hi"), netutils.NewNetAddr("udp", peer))
			written <- err
		}()
		return written
	}
	pc.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if err := recv(t, write("198.51.100.7:53"), "the deadline to end the first write"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first WriteTo past its deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	pc.SetWriteDeadline(time.Time{})
	written := write("198.51.100.8:53")
	// The deadline may have cut the first write's dial before its exec was sent.
	for line := ""; line != "stall 198.51.100.8 53"; {
		line = recv(t, up.stalls, "the second write's exec request")
	}
	pc.Close()
	if err := recv(t, written, "Close to end the second write"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo across Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPWritesOverASilentConnectionLeaveNoGoroutines(t *testing.T) {
	up, base := newUpstream(), &clientBase{}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		// Every session's command would otherwise wait for room in the upstream's queue.
		for {
			select {
			case <-up.commands:
			case <-stop:
				return
			}
		}
	}()
	n := dialServer(t, base, serveExec(t, up), withCredentials())
	pc, err := n.ListenPacket(timeout(t), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("hi"), netutils.NewNetAddr("udp", "198.51.100.1:53")); err != nil {
		t.Fatal(err)
	}
	base.mute()
	before := runtime.NumGoroutine()
	for i := range 100 {
		pc.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
		pc.WriteTo([]byte("hi"), netutils.NewNetAddr("udp", fmt.Sprintf("198.51.100.%d:53", 2+i)))
	}
	pc.Close()
	// What the writes left waiting on the silent connection ends once the client drops it.
	for wait := time.Now().Add(10 * time.Second); runtime.NumGoroutine() > before+10; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(wait) {
			t.Fatalf("goroutines = %d after the writes, %d before; want none left behind", runtime.NumGoroutine(), before)
		}
	}
}

func TestUDPRefusesInvalidPeersBeforeAnyChannel(t *testing.T) {
	up, base := newUpstream(), &clientBase{}
	n := dialServer(t, base, serveExec(t, up), withCredentials())
	ctx := timeout(t)
	pc, err := n.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, address := range []string{"-oProxyCommand=x:1", "a b:1", "a;b:1", "host:65536", "host:x", "host"} {
		if _, err := pc.WriteTo([]byte("hi"), netutils.NewNetAddr("udp", address)); err == nil || errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Errorf("WriteTo(%q) = %v, want the peer refused", address, err)
		}
		if conn, err := n.DialContext(ctx, "udp", address); err == nil || errors.Is(err, permuteproxy.ErrUnsupported) {
			if conn != nil {
				conn.Close()
			}
			t.Errorf("dial udp %q = %v, want the peer refused", address, err)
		}
	}
	if base.dials.Load() != 0 || up.dials.Load() != 0 {
		t.Fatalf("client dials %d, server commands %d; want the peers refused before any I/O", base.dials.Load(), up.dials.Load())
	}
}

func TestMalformedUDPCommandFailsClientBuild(t *testing.T) {
	n, err := permuteproxy.Engine{Base: &countingNetwork{}}.Client(chain(permuteproxy.Options{"udp_command": "socat - UDP:%h:%p"}, "127.0.0.1:1"))
	if err != nil {
		t.Fatalf("Client() with a well-formed udp_command = %v", err)
	}
	n.(io.Closer).Close()
	for _, command := range []string{"", "nc -u '%h' %p", "nc -u %h %x", "nc -u %h %p 'oops", `nc -u %h %p \`, " ", "# %h %p"} {
		base := &countingNetwork{}
		if _, err := (permuteproxy.Engine{Base: base}).Client(chain(permuteproxy.Options{"udp_command": command}, "127.0.0.1:1")); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("Client() with udp_command %q = %v, want ErrInvalidChain", command, err)
		}
		if got := base.calls.Load(); got != 0 {
			t.Errorf("udp_command %q: network calls = %d, want none", command, got)
		}
	}
}

func TestCustomUDPCommandReachesServer(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials("udp_command", "socat -T 30 - UDP:%h:%p"))
	conn, err := n.DialContext(timeout(t), "udp", "198.51.100.7:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "socat -T 30 - UDP:198.51.100.7:53|ping")
	if got, want := recv(t, up.commands, "the command").line, "socat -T 30 - UDP:198.51.100.7:53"; got != want {
		t.Fatalf("server ran %q, want %q", got, want)
	}
}

func TestSSHBaseRefusesPacketsOfLayersKeepingBoundaries(t *testing.T) {
	up := newUpstream()
	base := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "test-ssh-framed"}}, Endpoint: permuteproxy.Endpoint{Network: "tcp", Address: echoTarget(t)}}
	n, err := permuteproxy.Engine{Base: base}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer n.(io.Closer).Close()
	ctx := timeout(t)
	conn, err := n.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "ping")
	if _, err := n.DialContext(ctx, "udp", "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("dial udp = %v, want ErrUnsupported", err)
	}
	if _, err := n.ListenPacket(ctx, "udp", ":0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("listen packet udp = %v, want ErrUnsupported", err)
	}
	if framedBinds.Load() != 0 || up.dials.Load() != 0 {
		t.Fatalf("framed binds %d, server commands %d; want the layer never handed the ssh client's datagrams", framedBinds.Load(), up.dials.Load())
	}
}
