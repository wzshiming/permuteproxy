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
		for _, c := range []permuteproxy.Chain{chain("cmd-packet", "socat - UDP:127.0.0.1:53")} {
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
		{Network: "cmd-packet", Address: "socat - UDP:127.0.0.1:53"},
	} {
		c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "test-datagrams"}}, Endpoint: endpoint}
		if err := c.Validate(); !errors.Is(err, permuteproxy.ErrInvalidChain) || !strings.Contains(err.Error(), "datagram boundaries") {
			t.Errorf("Validate(test-datagrams over %s) = %v, want ErrInvalidChain since a command's stream keeps no datagram boundaries", endpoint.Network, err)
		}
	}
}
