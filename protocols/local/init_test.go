package local

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func init() {
	// test-datagrams needs datagram boundaries, as a QUIC or DTLS layer does.
	permuteproxy.RegisterLayer("test-datagrams", permuteproxy.LayerSpec{
		Kind:     permuteproxy.LayerAdapter,
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

func TestNetworkRegistrations(t *testing.T) {
	for _, tt := range []struct {
		uri   string
		want  permuteproxy.Endpoint // the address as the network's AddressKind reads it
		plane permuteproxy.Plane
	}{
		{"tcp://127.0.0.1:80/p", permuteproxy.Endpoint{Network: "tcp", Address: "127.0.0.1:80"}, permuteproxy.Stream},
		{"udp://127.0.0.1:53/p", permuteproxy.Endpoint{Network: "udp", Address: "127.0.0.1:53"}, permuteproxy.Packet},
		{"unix://./s.sock", permuteproxy.Endpoint{Network: "unix", Address: "./s.sock"}, permuteproxy.Stream},
		{"unixgram://./s.sock", permuteproxy.Endpoint{Network: "unixgram", Address: "./s.sock"}, permuteproxy.Packet},
		{"cmd:nc host 1", permuteproxy.Endpoint{Network: "cmd", Address: "nc host 1"}, permuteproxy.Stream},
		{"cmd-nc://127.0.0.1:80", permuteproxy.Endpoint{Network: "cmd-nc", Address: "127.0.0.1:80"}, permuteproxy.Stream},
		{"cmd-nc-unix://./s.sock", permuteproxy.Endpoint{Network: "cmd-nc-unix", Address: "./s.sock"}, permuteproxy.Stream},
		{"cmd-nc-udp://127.0.0.1:53", permuteproxy.Endpoint{Network: "cmd-nc-udp", Address: "127.0.0.1:53"}, permuteproxy.Packet},
		{"cmd-packet:ssh host nc -u 1.1.1.1 53", permuteproxy.Endpoint{Network: "cmd-packet", Address: "ssh host nc -u 1.1.1.1 53"}, permuteproxy.Packet},
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

func TestCommandNetworksDialCmdOnTheBase(t *testing.T) {
	for _, tt := range []struct {
		network, address string
		plane            permuteproxy.Plane
		want             string
	}{
		{"cmd-nc", "127.0.0.1:80", permuteproxy.Stream, "dial cmd nc 127.0.0.1 80"},
		{"cmd-nc-unix", "/tmp/a b.sock", permuteproxy.Stream, "dial cmd nc -U '/tmp/a b.sock'"},
		{"cmd-nc-udp", "127.0.0.1:53", permuteproxy.Packet, "dial cmd nc -u -w 30 127.0.0.1 53"},
		{"cmd-packet", "ssh host nc -u 1.1.1.1 53", permuteproxy.Packet, "dial cmd ssh host nc -u 1.1.1.1 53"},
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
		// Local owns the socket file cleanup, so listening keeps the network's own name.
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

func TestSystemNetworksWithoutABase(t *testing.T) {
	ctx := context.Background()
	for _, network := range []string{"tcp", "udp", "unix", "unixgram"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if strings.HasPrefix(network, "unix") {
				if network == "unixgram" && runtime.GOOS == "windows" {
					t.Skip("unixgram needs a POSIX system")
				}
				address = socketPath(t)
			}
			tr, err := permuteproxy.TransportEngine{}.Transport(chain(network, address))
			if err != nil {
				t.Fatal(err)
			}
			var peer net.Addr
			if tr.Planes() == permuteproxy.Packet {
				pc, err := tr.ListenPacket(ctx)
				if err != nil {
					t.Fatalf("ListenPacket without a Base = %v, want the registered Local binding", err)
				}
				peer = testutils.ServePacketEcho(t, pc)
			} else {
				ln, err := tr.Listen(ctx)
				if err != nil {
					t.Fatalf("Listen without a Base = %v, want the registered Local listening", err)
				}
				peer = testutils.ServeEcho(t, ln)
			}
			tr, err = permuteproxy.TransportEngine{}.Transport(chain(network, peer.String()))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := tr.Dial(ctx, tr.Planes())
			if err != nil {
				t.Fatalf("Dial without a Base = %v, want the registered Local dialing", err)
			}
			defer conn.Close()
			testutils.RoundTrip(t, conn, "ping", "ping")
		})
	}
}

func TestCommandNetworksRefuseInvalidValues(t *testing.T) {
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
	// Local listens on cmd-nc-unix itself, so it refuses such a path before nc starts too.
	ln, err := Network.Listen(context.Background(), "cmd-nc-unix", "-x.sock")
	if err == nil {
		ln.Close()
	}
	if !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Fatalf("Listen(cmd-nc-unix %q) = %v, want ErrInvalidChain", "-x.sock", err)
	}
}

// echoes sends msg as one datagram to conn's fixed peer and wants it back from that peer.
func echoes(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("conn is not a net.PacketConn")
	}
	if _, err := pc.WriteTo([]byte(msg), conn.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("ReadFrom = %q, %v; want %q echoed", buf[:n], err, msg)
	}
	if from.String() != conn.RemoteAddr().String() {
		t.Fatalf("datagram from %v, want the fixed peer %v", from, conn.RemoteAddr())
	}
}

// spawning is a Local recording each command it starts; the test's end kills and reaps them.
func spawning(t *testing.T) (*Local, *[]net.Conn) {
	t.Helper()
	var started []net.Conn
	n := &Local{}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		conn, err := n.command(ctx, name, args...)
		if err == nil {
			started = append(started, conn)
		}
		return conn, err
	}
	t.Cleanup(func() {
		for _, conn := range started {
			process(t, conn).Kill()
			reaped(t, conn)
		}
	})
	return n, &started
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
	nc := (*started)[0]
	process(t, nc).Kill()
	reaped(t, nc)
	first.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := first.Read(make([]byte, 64)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after nc exited = %v, want EOF", err)
	}
	if got := len(*started); got != 1 {
		t.Fatalf("%d commands after one Dial, want the conn to keep its own", got)
	}
	second, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := len(*started); got != 2 {
		t.Fatalf("%d commands after two Dials, want one each", got)
	}
	echoes(t, second, "pong")
}

func TestCommandPacketRunsItsAddress(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PERMUTEPROXY_FAKE_SOCAT", "1")
	address := cmdutils.Quote([]string{exe, "socat", "-", "UDP:" + testutils.UDPEcho(t).String()})
	tr, err := permuteproxy.TransportEngine{}.Transport(chain("cmd-packet", address))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(context.Background(), permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != address {
		t.Fatalf("peer %q, want the command line as written %q", got, address)
	}
	echoes(t, conn, "ping")
}

func TestCommandPacketNetworksRefuseListening(t *testing.T) {
	ctx := context.Background()
	for base, e := range map[string]permuteproxy.TransportEngine{"without a Base": {}, "with Local as Base": {Base: Network}} {
		for _, c := range []permuteproxy.Chain{chain("cmd-nc-udp", "127.0.0.1:53"), chain("cmd-packet", "socat - UDP:127.0.0.1:53")} {
			tr, err := e.Transport(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tr.Listen(ctx); !errors.Is(err, permuteproxy.ErrUnsupported) {
				t.Errorf("Listen on %s %s = %v, want ErrUnsupported", c.Endpoint.Network, base, err)
			}
			if _, err := tr.ListenPacket(ctx); !errors.Is(err, permuteproxy.ErrUnsupported) {
				t.Errorf("ListenPacket on %s %s = %v, want ErrUnsupported", c.Endpoint.Network, base, err)
			}
		}
	}
}

func TestCommandPacketNetworksRefuseLayersNeedingDatagrams(t *testing.T) {
	for _, endpoint := range []permuteproxy.Endpoint{
		{Network: "cmd-nc-udp", Address: "127.0.0.1:53"},
		{Network: "cmd-packet", Address: "socat - UDP:127.0.0.1:53"},
	} {
		c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "test-datagrams"}}, Endpoint: endpoint}
		if err := c.Validate(); !errors.Is(err, permuteproxy.ErrInvalidChain) || !strings.Contains(err.Error(), "datagram boundaries") {
			t.Errorf("Validate(test-datagrams over %s) = %v, want ErrInvalidChain since a command's stream keeps no datagram boundaries", endpoint.Network, err)
		}
	}
}
