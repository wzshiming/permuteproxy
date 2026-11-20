package permuteproxy_test

import (
	"context"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols/local"
)

// sshExec serves the ssh layer with exec allowed to user u with password p, running commands
// through upstream, and returns a client of it.
func sshExec(t *testing.T, upstream permuteproxy.Network) permuteproxy.Network {
	t.Helper()
	c := parse(t, "ssh://u:p@127.0.0.1:0?allow_exec=true")
	base := newProbe(system)
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	c.Layers[0].Options = permuteproxy.Options{"username": "u", "password": "p"}
	n, err := permuteproxy.Engine{}.Client(c)
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
	tr, err := permuteproxy.Engine{Base: sshExec(t, commands)}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd-nc-udp", Address: udpEcho(t).String()}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, []byte("ping"))
	if got := commands.dials.Load(); got != 1 {
		t.Fatalf("ssh server ran %d commands, want the one nc", got)
	}
}

func TestSSHClientDialsUDPThroughNetcat(t *testing.T) {
	requireNetcat(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commands := newProbe(local.Network)
	conn := dialPacket(t, ctx, sshExec(t, commands), udpEcho(t).String())
	echoed(t, conn, []byte("ping"))
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
	base := newProbe(system)
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	n, err := permuteproxy.Engine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	conn := dialPacket(t, ctx, n, udpEcho(t).String())
	echoed(t, conn, []byte("ping"))
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
	tr, err := permuteproxy.Engine{Base: sshExec(t, commands)}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd-nc", Address: tcpEcho(t)}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, streamPayload)
	if got := commands.dials.Load(); got != 1 {
		t.Fatalf("ssh server ran %d commands, want the one nc", got)
	}
}
