package local

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var errHop = errors.New("hop: not listening")

// hop records what an Engine asks of it and answers each dial with a pipe named after the dialed address.
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

func TestCommandNetworksDialCmdOnTheBase(t *testing.T) {
	for _, tt := range []struct {
		network, address string
		plane            permuteproxy.Plane
		want             string
	}{
		{"cmd-nc", "127.0.0.1:80", permuteproxy.Stream, "dial cmd nc 127.0.0.1 80"},
		{"cmd-nc-unix", "/tmp/a b.sock", permuteproxy.Stream, "dial cmd nc -U '/tmp/a b.sock'"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			base := &hop{}
			tr, err := permuteproxy.Engine{Base: base}.Transport(chain(tt.network, tt.address))
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
			tr, err := permuteproxy.Engine{Base: base}.Transport(chain(tt.network, tt.address))
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
	} {
		switch _, err := (permuteproxy.Engine{}).Transport(chain(tt.network, tt.address)); {
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
