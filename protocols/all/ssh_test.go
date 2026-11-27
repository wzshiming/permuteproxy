package all_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
	"github.com/wzshiming/permuteproxy/protocols/local"
)

// sshExec serves ssh with exec allowed for u:p, running commands through upstream, and returns its client.
func sshExec(t *testing.T, upstream permuteproxy.Network) permuteproxy.Network {
	t.Helper()
	c := parse(t, "ssh://u:p@127.0.0.1:0?allow_exec=true")
	base := newProbe(testutils.System{})
	_, done := start(t, permuteproxy.ServerEngine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	c.Layers[0].Options = permuteproxy.Options{"username": "u", "password": "p"}
	n, err := permuteproxy.ClientEngine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeIf(n) })
	return n
}

func TestNetcatUDPOverSSHExec(t *testing.T) {
	requireNetcat(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commands := newProbe(local.Network)
	echo, received := watchedUDPEcho(t)
	tr, err := permuteproxy.TransportEngine{Base: sshExec(t, commands)}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd-nc-udp", Address: echo.String()}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, []byte("ping"))
	testutils.Wait(t, received, "the datagram reaching the udp echo")
	if got := commands.dials.Load(); got != 1 {
		t.Fatalf("ssh server ran %d commands, want the one nc", got)
	}
}

func TestSSHClientDialsUDPThroughNetcat(t *testing.T) {
	requireNetcat(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commands := newProbe(local.Network)
	echo, received := watchedUDPEcho(t)
	conn := dialPacket(t, ctx, sshExec(t, commands), echo.String())
	echoed(t, conn, []byte("ping"))
	testutils.Wait(t, received, "the datagram reaching the udp echo")
	if got := commands.dials.Load(); got != 1 {
		t.Fatalf("ssh server ran %d commands, want the one nc", got)
	}
}

func TestSOCKS5AssociationOverSSHUpstream(t *testing.T) {
	requireNetcat(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commands := newProbe(local.Network)
	upstream := newProbe(sshExec(t, commands))
	c := parse(t, "socks5://127.0.0.1:0")
	base := newProbe(testutils.System{})
	_, done := start(t, permuteproxy.ServerEngine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	n, err := permuteproxy.ClientEngine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	echo, received := watchedUDPEcho(t)
	conn := dialPacket(t, ctx, n, echo.String())
	echoed(t, conn, []byte("ping"))
	testutils.Wait(t, received, "the datagram reaching the udp echo")
	// The association's outgoing socket is the ssh client's udp, which runs nc on the ssh server.
	if upstream.packets.Load() != 1 || upstream.dials.Load() != 0 {
		t.Fatalf("upstream packets %d dials %d, want 1 and 0", upstream.packets.Load(), upstream.dials.Load())
	}
	if got := commands.dials.Load(); got != 1 {
		t.Fatalf("ssh server ran %d commands, want the one nc", got)
	}
}

func TestNetcatOverSSHExecCarriesAStream(t *testing.T) {
	requireNetcat(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commands := newProbe(local.Network)
	echo, accepted := tcpEcho(t)
	tr, err := permuteproxy.TransportEngine{Base: sshExec(t, commands)}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd-nc", Address: echo}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, streamPayload)
	testutils.Wait(t, accepted, "nc's conn reaching the tcp echo")
	if got := commands.dials.Load(); got != 1 {
		t.Fatalf("ssh server ran %d commands, want the one nc", got)
	}
}

// lossyCalls counts every call on a network, reporting what it reports lossy.
type lossyCalls struct {
	permuteproxy.Network
	calls atomic.Int32
}

func (n *lossyCalls) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	n.calls.Add(1)
	return n.Network.DialContext(ctx, network, address)
}

func (n *lossyCalls) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	n.calls.Add(1)
	return n.Network.Listen(ctx, network, address)
}

func (n *lossyCalls) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	n.calls.Add(1)
	return n.Network.ListenPacket(ctx, network, address)
}

func (n *lossyCalls) Lossy(network string) bool {
	l, ok := n.Network.(permuteproxy.LossyNetwork)
	return ok && l.Lossy(network)
}

// refused wants each operation refused with ErrUnsupported and no call on base.
func refused(t *testing.T, base *lossyCalls, ops map[string]error) {
	t.Helper()
	for op, err := range ops {
		if !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Errorf("%s = %v, want ErrUnsupported", op, err)
		}
	}
	if got := base.calls.Load(); got != 0 {
		t.Errorf("%d calls reached the ssh client, want none", got)
	}
}

func TestLayersOverSSHRefuseItsLossyDatagrams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The ssh client derives udp from nc's output through dgram, which keeps no datagram boundaries.
	ssh := sshExec(t, newProbe(local.Network))
	t.Run("ss+udp", func(t *testing.T) {
		base := &lossyCalls{Network: ssh}
		n, err := permuteproxy.ClientEngine{Base: base}.Client(parse(t, "ss+udp://127.0.0.1:1"))
		if err != nil {
			t.Fatal(err)
		}
		defer closeIf(n)
		_, dial := n.DialContext(ctx, "udp", "127.0.0.1:1")
		_, listen := n.ListenPacket(ctx, "udp", ":0")
		refused(t, base, map[string]error{"dial udp": dial, "listen packet udp": listen})
	})
	t.Run("quic+udp", func(t *testing.T) {
		base := &lossyCalls{Network: ssh}
		tr, err := permuteproxy.TransportEngine{Base: base}.Transport(parse(t, "quic+udp://127.0.0.1:1?tls_skip_verify=true&tls_self_signed=true"))
		if err != nil {
			t.Fatal(err)
		}
		defer closeIf(tr)
		_, dial := tr.Dial(ctx, permuteproxy.Stream)
		_, listen := tr.Listen(ctx)
		refused(t, base, map[string]error{"dial": dial, "listen": listen})
	})
	t.Run("socks5", func(t *testing.T) {
		c := parse(t, "socks5://127.0.0.1:0")
		proxyBase := newProbe(testutils.System{})
		_, done := start(t, permuteproxy.ServerEngine{Base: proxyBase}, c)
		c.Endpoint.Address = waitBound(t, proxyBase, done).String()
		base := &lossyCalls{Network: ssh}
		n, err := permuteproxy.ClientEngine{Base: base}.Client(c)
		if err != nil {
			t.Fatal(err)
		}
		defer closeIf(n)
		_, dial := n.DialContext(ctx, "udp", testutils.UDPEcho(t).String())
		_, listen := n.ListenPacket(ctx, "udp", ":0")
		refused(t, base, map[string]error{"dial udp": dial, "listen packet udp": listen})
		if body, err := fetch(ctx, n, okTarget(t)); err != nil || body != "OK" {
			t.Fatalf("tcp through socks5 over the ssh client: %q, %v", body, err)
		}
		if got := base.calls.Load(); got != 1 {
			t.Fatalf("calls on the ssh client = %d, want the one control conn", got)
		}
	})
}
