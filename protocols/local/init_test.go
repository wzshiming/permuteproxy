package local

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// socketPath stays under the unix socket path limit, which t.TempDir's test-named paths exceed.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "local")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func chain(network, address string) permuteproxy.Chain {
	return permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: network, Address: address}}
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
