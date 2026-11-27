package netcat

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
	"github.com/wzshiming/permuteproxy/protocols/local"
)

func TestTemplates(t *testing.T) {
	for _, tc := range []struct {
		name, got, want string
	}{
		{"DialTCP", DialTCP, "nc %h %p"},
		{"ListenTCP", ListenTCP, "nc -l %h %p"},
		{"DialUnix", DialUnix, "nc -U %h"},
		{"ListenUnix", ListenUnix, "nc -Ul %h"},
		{"DialUDP", DialUDP, "nc -u -w 30 %h %p"},
		{"ListenUDP", ListenUDP, "nc -u -l %h %p"},
		{"DialUnixgram", DialUnixgram, "nc -U -u -w 30 %h"},
		{"ListenUnixgram", ListenUnixgram, "nc -U -u -l %h"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func init() {
	// test-datagrams needs datagram boundaries, as a QUIC or DTLS layer does.
	permuteproxy.RegisterLayer("test-datagrams", permuteproxy.LayerSpec{
		Requires: permuteproxy.Packet,
		Provides: permuteproxy.Packet,
		NewAdapter: func(permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
			return &permuteproxy.AdapterFuncs{Packet: &permuteproxy.Link{}}, nil
		},
	})
}

var errHop = errors.New("hop: not listening")

// hop records what a TransportEngine asks of it; each dial gets a pipe named after the dialed address.
type hop struct {
	calls []string
	peers []net.Conn
}

func (h *hop) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	h.calls = append(h.calls, "dial "+network+" "+address)
	conn, peer := net.Pipe()
	h.peers = append(h.peers, peer)
	return netutils.ConnWithAddr(conn, nil, netutils.NewNetAddr(network, address)), nil
}

func (h *hop) Listen(_ context.Context, network, address string) (net.Listener, error) {
	h.calls = append(h.calls, "listen "+network+" "+address)
	return nil, errHop
}

func (h *hop) ListenPacket(_ context.Context, network, address string) (net.PacketConn, error) {
	h.calls = append(h.calls, "listen packet "+network+" "+address)
	return nil, errHop
}

func TestNetcatNetworkRegistrations(t *testing.T) {
	for _, tt := range []struct {
		uri   string
		want  permuteproxy.Endpoint // the address as the network's AddressKind reads it
		plane permuteproxy.Plane
	}{
		{"cmd-nc://127.0.0.1:80", permuteproxy.Endpoint{Network: "cmd-nc", Address: "127.0.0.1:80"}, permuteproxy.Stream},
		{"cmd-nc-unix://./s.sock", permuteproxy.Endpoint{Network: "cmd-nc-unix", Address: "./s.sock"}, permuteproxy.Stream},
		{"cmd-nc-udp://127.0.0.1:53", permuteproxy.Endpoint{Network: "cmd-nc-udp", Address: "127.0.0.1:53"}, permuteproxy.Packet},
		{"cmd-nc-unixgram://./s.sock", permuteproxy.Endpoint{Network: "cmd-nc-unixgram", Address: "./s.sock"}, permuteproxy.Packet},
	} {
		t.Run(tt.want.Network, func(t *testing.T) {
			c, err := permuteproxy.ParseURI(tt.uri)
			if err != nil {
				t.Fatal(err)
			}
			if c.Endpoint != tt.want || len(c.Layers) != 0 {
				t.Fatalf("ParseURI(%q) = %+v, want the endpoint %+v", tt.uri, c, tt.want)
			}
			tr, err := permuteproxy.TransportEngine{}.Transport(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := tr.Planes(); got != tt.plane {
				t.Fatalf("%s offers %v, want %v", tt.want.Network, got, tt.plane)
			}
		})
	}
}

func TestNetcatNetworksDialCmdOnTheBase(t *testing.T) {
	for _, tt := range []struct {
		network, address string
		plane            permuteproxy.Plane
		want             string
	}{
		{"cmd-nc", "127.0.0.1:80", permuteproxy.Stream, "dial cmd nc 127.0.0.1 80"},
		{"cmd-nc-unix", "/tmp/a b.sock", permuteproxy.Stream, "dial cmd nc -U '/tmp/a b.sock'"},
		{"cmd-nc-udp", "127.0.0.1:53", permuteproxy.Packet, "dial cmd nc -u -w 30 127.0.0.1 53"},
		{"cmd-nc-unixgram", "/tmp/a b.sock", permuteproxy.Packet, "dial cmd nc -U -u -w 30 '/tmp/a b.sock'"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			base := &hop{}
			tr, err := permuteproxy.TransportEngine{Base: base}.Transport(chain(tt.network, tt.address))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := tr.Dial(context.Background(), tt.plane)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if want := []string{tt.want}; !slices.Equal(base.calls, want) {
				t.Fatalf("base calls = %q, want %q", base.calls, want)
			}
			go base.peers[0].Write([]byte("x"))
			if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
				t.Fatalf("conn does not carry what the base's command writes: %v", err)
			}
		})
	}
}

func TestNetcatNetworksListenOnTheBase(t *testing.T) {
	for _, tt := range []struct{ network, address, want string }{
		{"cmd-nc", "127.0.0.1:80", "listen cmd nc -l 127.0.0.1 80"},
		// A Local owns the socket file cleanup, so listening keeps the network's own name.
		{"cmd-nc-unix", "/tmp/a b.sock", "listen cmd-nc-unix /tmp/a b.sock"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			base := &hop{}
			tr, err := permuteproxy.TransportEngine{Base: base}.Transport(chain(tt.network, tt.address))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tr.Listen(context.Background()); !errors.Is(err, errHop) {
				t.Fatalf("Listen = %v, want the base's %v", err, errHop)
			}
			if want := []string{tt.want}; !slices.Equal(base.calls, want) {
				t.Fatalf("base calls = %q, want %q", base.calls, want)
			}
		})
	}
}

func TestNetcatUnixListensWithoutABase(t *testing.T) {
	tr, err := permuteproxy.TransportEngine{}.Transport(chain("cmd-nc-unix", socketPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tr.Listen(context.Background())
	if err != nil {
		t.Fatalf("Listen without a Base = %v, want the registered Local listening", err)
	}
	ln.Close()
}

func TestNetcatNetworksRefuseInvalidValues(t *testing.T) {
	for _, tt := range []struct {
		network, address string
		ok               bool
	}{
		{"cmd-nc", "127.0.0.1:1", true},
		{"cmd-nc", "-oProxyCommand=x:1", false},
		{"cmd-nc", "a b:1", false},
		{"cmd-nc", "a'b:1", false},
		{"cmd-nc", `a"b:1`, false},
		{"cmd-nc", "h:65536", false},
		{"cmd-nc-unix", "./s.sock", true},
		{"cmd-nc-unix", "-x.sock", false},
		{"cmd-nc-udp", "127.0.0.1:53", true},
		{"cmd-nc-udp", "-h:53", false},
		{"cmd-nc-unixgram", "./s.sock", true},
		{"cmd-nc-unixgram", "-x.sock", false},
		{"cmd-nc-udp", "a b:53", false},
		{"cmd-nc-udp", "a'b:53", false},
		{"cmd-nc-udp", "h:65536", false},
	} {
		switch _, err := (permuteproxy.TransportEngine{}).Transport(chain(tt.network, tt.address)); {
		case tt.ok && err != nil:
			t.Errorf("Transport(%s %q) = %v, want it built", tt.network, tt.address, err)
		case !tt.ok && !errors.Is(err, permuteproxy.ErrInvalidChain):
			t.Errorf("Transport(%s %q) = %v, want ErrInvalidChain before any command starts", tt.network, tt.address, err)
		}
	}
	// Network listens on cmd-nc-unix itself, so it refuses such a path before nc starts too.
	ln, err := Network.Listen(context.Background(), "cmd-nc-unix", "-x.sock")
	if err == nil {
		ln.Close()
	}
	if !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Fatalf("Listen(cmd-nc-unix %q) = %v, want ErrInvalidChain", "-x.sock", err)
	}
}

func TestNetcatUDPEcho(t *testing.T) {
	requireCommand(t, "nc")
	n, _ := spawning(t)
	peer := testutils.UDPEcho(t)
	tr, err := permuteproxy.TransportEngine{Base: n}.Transport(chain("cmd-nc-udp", peer.String()))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(context.Background(), permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoes(t, conn, "ping")
	echoes(t, conn, "pong")
	if _, err := conn.(net.PacketConn).WriteTo([]byte("ping"), peer); err == nil {
		t.Fatalf("WriteTo %v succeeded, want only the fixed peer %v reachable", peer, conn.RemoteAddr())
	}
}

func TestNetcatUDPCommandPerDial(t *testing.T) {
	requireCommand(t, "nc")
	ctx := context.Background()
	n, started := spawning(t)
	tr, err := permuteproxy.TransportEngine{Base: n}.Transport(chain("cmd-nc-udp", testutils.UDPEcho(t).String()))
	if err != nil {
		t.Fatal(err)
	}
	first, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	echoes(t, first, "ping")
	nc := started()[0]
	process(t, nc).Kill()
	reaped(t, nc)
	first.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := first.Read(make([]byte, 64)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after nc exited = %v, want EOF", err)
	}
	if got := len(started()); got != 1 {
		t.Fatalf("%d commands after one Dial, want the conn to keep its own", got)
	}
	second, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := len(started()); got != 2 {
		t.Fatalf("%d commands after two Dials, want one each", got)
	}
	echoes(t, second, "pong")
}

// cmd-nc-udp has no stream to listen for; binding it is asked of the base under its own name.
func TestNetcatUDPBindsOnTheBase(t *testing.T) {
	ctx := context.Background()
	base := &hop{}
	tr, err := permuteproxy.TransportEngine{Base: base}.Transport(chain("cmd-nc-udp", "127.0.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("Listen on cmd-nc-udp = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, errHop) {
		t.Errorf("ListenPacket on cmd-nc-udp = %v, want the base's %v", err, errHop)
	}
	if want := []string{"listen packet cmd-nc-udp 127.0.0.1:53"}; !slices.Equal(base.calls, want) {
		t.Fatalf("base calls = %q, want %q", base.calls, want)
	}
}

// serveOnePeer answers the first datagram pc reads with pong, to the peer ReadFrom reports.
func serveOnePeer(pc net.PacketConn) error {
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		return err
	}
	// The pings the client repeated until nc was bound may arrive merged.
	if !strings.HasPrefix(string(buf[:n]), "ping") {
		return errors.New("read " + string(buf[:n]))
	}
	_, err = pc.WriteTo([]byte("pong"), from)
	return err
}

// pingUntilPong sends ping to address until pong comes back, as nc binds some time after it started.
func pingUntilPong(t *testing.T, address string) {
	t.Helper()
	peer, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	// Unconnected, so that a ping refused before nc is bound does not fail the next read.
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	buf := make([]byte, 64)
	for i := 0; i < 200; i++ {
		if _, err := sock.WriteTo([]byte("ping"), peer); err != nil {
			t.Fatal(err)
		}
		sock.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if n, _, err := sock.ReadFrom(buf); err == nil {
			if string(buf[:n]) != "pong" {
				t.Fatalf("read %q, want pong", buf[:n])
			}
			return
		}
	}
	t.Fatal("no pong from the nc listening on udp")
}

func TestNetcatUDPListenServesOnePeer(t *testing.T) {
	requireCommand(t, "nc")
	t.Run("endpoint", func(t *testing.T) {
		n, started := spawning(t)
		address := freeUDP(t)
		tr, err := permuteproxy.TransportEngine{Base: n}.Transport(chain("cmd-nc-udp", address))
		if err != nil {
			t.Fatal(err)
		}
		pc, err := tr.ListenPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		if got := pc.LocalAddr(); got.Network() != "udp" || got.String() != address {
			t.Fatalf("LocalAddr = %s %s, want udp %s", got.Network(), got, address)
		}
		served := make(chan error, 1)
		go func() { served <- serveOnePeer(pc) }()
		pingUntilPong(t, address)
		if err := <-served; err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteTo([]byte("x"), netutils.NewNetAddr("udp", "127.0.0.1:9")); err == nil {
			t.Fatal("WriteTo another address succeeded, want only nc's single peer reachable")
		}
		if got := len(started()); got != 1 {
			t.Fatalf("%d commands for one socket, want the single nc", got)
		}
	})
	t.Run("client", func(t *testing.T) {
		n, started := spawning(t)
		address := freeUDP(t)
		client, err := NewClient(n, "")
		if err != nil {
			t.Fatal(err)
		}
		pc, err := client.ListenPacket(context.Background(), "udp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		served := make(chan error, 1)
		go func() { served <- serveOnePeer(pc) }()
		pingUntilPong(t, address)
		if err := <-served; err != nil {
			t.Fatal(err)
		}
		if got := len(started()); got != 1 {
			t.Fatalf("%d commands for one socket, want the single nc", got)
		}
	})
}

// cmd-nc-unixgram binds through nc -U -u -l on a Local, and is asked of a base under its own name.
func TestNetcatUnixgramBinds(t *testing.T) {
	ctx := context.Background()
	base := &hop{}
	tr, err := permuteproxy.TransportEngine{Base: base}.Transport(chain("cmd-nc-unixgram", "./s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, errHop) {
		t.Errorf("ListenPacket on cmd-nc-unixgram = %v, want the base's %v", err, errHop)
	}
	if want := []string{"listen packet cmd-nc-unixgram ./s.sock"}; !slices.Equal(base.calls, want) {
		t.Fatalf("base calls = %q, want %q", base.calls, want)
	}
	argv := make(chan []string, 1)
	n := Local{&local.Local{}}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		argv <- append([]string{name}, args...)
		conn, _ := net.Pipe()
		return conn, nil
	}
	pc, err := n.ListenPacket(ctx, "cmd-nc-unixgram", "./s.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if got, want := <-argv, []string{"nc", "-U", "-u", "-l", "./s.sock"}; !slices.Equal(got, want) {
		t.Fatalf("binding runs %q, want %q", got, want)
	}
	if got := pc.LocalAddr(); got.Network() != "unixgram" || got.String() != "./s.sock" {
		t.Fatalf("LocalAddr = %s %s, want unixgram ./s.sock", got.Network(), got)
	}
}

// freeUDP is a udp address nothing is bound to any more.
func freeUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// Without a Base the registered Network binds cmd-nc-udp, while a plain local.Local refuses it.
func TestNetcatUDPBindsWithoutABase(t *testing.T) {
	requireCommand(t, "nc")
	tr, err := permuteproxy.TransportEngine{}.Transport(chain("cmd-nc-udp", freeUDP(t)))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := tr.ListenPacket(context.Background())
	if err != nil {
		t.Fatalf("ListenPacket without a Base = %v, want the registered Network binding", err)
	}
	pc.Close()
	if _, err := tr.Listen(context.Background()); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("Listen on cmd-nc-udp = %v, want ErrUnsupported", err)
	}
	if _, err := Network.Local.ListenPacket(context.Background(), "cmd-nc-udp", "127.0.0.1:53"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("local.Network.ListenPacket(cmd-nc-udp) = %v, want ErrUnsupported", err)
	}
	if _, err := Network.ListenPacket(context.Background(), "cmd-nc-udp", "ho;st:53"); err == nil {
		t.Error("ListenPacket bound a host a shell would not read as plain text")
	}
}

func TestNetcatUDPRefusesLayersNeedingDatagrams(t *testing.T) {
	for _, endpoint := range []permuteproxy.Endpoint{
		{Network: "cmd-nc-udp", Address: "127.0.0.1:53"},
		{Network: "cmd-nc-unixgram", Address: "./s.sock"},
	} {
		c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "test-datagrams"}}, Endpoint: endpoint}
		if err := c.Validate(); !errors.Is(err, permuteproxy.ErrInvalidChain) || !strings.Contains(err.Error(), "datagram boundaries") {
			t.Errorf("Validate(test-datagrams over %s) = %v, want ErrInvalidChain since a command's stream keeps no datagram boundaries", endpoint.Network, err)
		}
	}
}
