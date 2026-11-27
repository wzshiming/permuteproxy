package permuteproxy

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestServerBindFailureReleasesCarriers(t *testing.T) {
	calls = nil
	base := NetworkFuncs{
		ListenFunc:       func(context.Context, string, string) (net.Listener, error) { return closeListener{}, nil },
		ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) { return nil, errLink },
	}
	srv, err := ServerEngine{Base: base}.Server(mk("", "test-ss"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	if err := testutils.Wait(t, done, "Run to return after the packet bind failed"); !errors.Is(err, errLink) {
		t.Fatalf("Run() = %v, want the packet bind error", err)
	}
	assertCalls(t, "carrier.close")
	if err := srv.Close(); err != nil {
		t.Fatalf("Close after the failed bind = %v", err)
	}
}

func TestServerBindsRequiredOrPreservedPlanes(t *testing.T) {
	calls = nil
	e := ServerEngine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		chain Chain
		serve []string
	}{
		{mk("", "test-socks5", "test-keep"), []string{"base.listen tcp 127.0.0.1:1", "test-keep.listener", "test-socks5.serve upstream=default"}},
		{mk("", "test-ss", "test-keep"), []string{"base.listen tcp 127.0.0.1:1", "test-keep.listener", "base.listenpacket udp 127.0.0.1:1", "test-ss.serve upstream=default", "test-ss.servepacket upstream=default"}},
	}
	for _, tt := range tests {
		srv, err := e.Server(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		assertRun(t, srv, tt.serve...)
	}
}

func TestServerFirstReturnCancelsOther(t *testing.T) {
	errServe := errors.New("serve failed")
	for _, first := range []Plane{Stream, Packet} {
		t.Run(first.String(), func(t *testing.T) {
			exits := make(chan error, 2)
			serve := func(ctx context.Context, plane Plane) error {
				err := errServe
				if plane != first {
					<-ctx.Done()
					err = ctx.Err()
				}
				exits <- err
				return err
			}
			funcs := &ServerFuncs{
				Serve:       func(ctx context.Context, _ net.Listener, _ Network) error { return serve(ctx, Stream) },
				ServePacket: func(ctx context.Context, _ net.PacketConn, _ Network) error { return serve(ctx, Packet) },
			}
			// The serves belong to this test, so the declared server is assembled directly.
			inner := &bound{network: &fakeNet{name: "base"}, stream: "tcp", packet: "udp", address: "x:1"}
			srv, err := declaredServer(0, Stream|Packet, funcs, nil).server(inner, testutils.System{}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := srv.Run(context.Background()); !errors.Is(err, errServe) {
				t.Fatalf("Run() = %v, want the error of the serve that returned first", err)
			}
			for _, want := range []error{errServe, context.Canceled} {
				select {
				case got := <-exits:
					if !errors.Is(got, want) {
						t.Fatalf("serve ended with %v, want %v", got, want)
					}
				default:
					t.Fatal("Run returned before both serves ended")
				}
			}
		})
	}
}

func TestServerStopReleasesCarriers(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			addrs := make(chan net.Addr, 1)
			accepted := make(chan struct{}, 1)
			ends := make(chan error, 2)
			funcs := &ServerFuncs{
				Serve: func(_ context.Context, ln net.Listener, _ Network) error {
					addrs <- ln.Addr()
					conn, err := ln.Accept()
					if err != nil {
						return err
					}
					accepted <- struct{}{}
					_, err = conn.Read(make([]byte, 1))
					ends <- err
					return err
				},
				ServePacket: func(_ context.Context, pc net.PacketConn, _ Network) error {
					_, _, err := pc.ReadFrom(make([]byte, 1))
					ends <- err
					return err
				},
			}
			inner := &bound{network: testutils.System{}, stream: "tcp", packet: "udp", address: "127.0.0.1:0"}
			srv, err := declaredServer(0, Stream|Packet, funcs, nil).server(inner, testutils.System{}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- srv.Run(ctx) }()
			addr := testutils.Wait(t, addrs, "bind")
			client, err := net.Dial("tcp", addr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			testutils.Wait(t, accepted, "accept")
			if stop == "cancel" {
				cancel()
			} else if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			if err := testutils.Wait(t, done, "Run returning"); err != nil {
				t.Fatalf("Run() = %v after the stop, want nil", err)
			}
			for i := 0; i < 2; i++ {
				if err := testutils.Wait(t, ends, "serve read"); err == nil {
					t.Fatal("a serve read its carrier after the stop")
				}
			}
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("client read = %v, want its accepted conn closed by the stop", err)
			}
			if conn, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
				conn.Close()
				t.Fatal("listener still open after the stop")
			}
		})
	}
}

func TestServerRejectsDeclarations(t *testing.T) {
	calls = nil
	e := ServerEngine{Base: &fakeNet{name: "base"}}
	schemes := []string{"nilproxy", "test-server-broken"}
	for name := range uncoveredServers {
		schemes = append(schemes, name)
	}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			if _, err := e.Server(mk("", scheme)); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Server() = %v, want ErrInvalidChain", err)
			}
			assertCalls(t)
		})
	}
	if _, err := e.Server(mk("", "test-server-broken")); !errors.Is(err, errDeclare) {
		t.Fatalf("Server() = %v, want the NewServer error kept", err)
	}
}

func TestServerRefusesCarrierWithNothingToBind(t *testing.T) {
	calls = nil
	e := ServerEngine{Base: &closableNet{fakeNet{name: "base"}}}
	lossy := ServerEngine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	for _, tt := range []struct {
		name   string
		engine ServerEngine
		chain  Chain
		want   []string
	}{
		{"NewServer over a stream carrier", e, mk("tcp", "test-packet-server", "closable"), []string{"closable.close"}},
		{"NewServer over lossy udp", lossy, mk("udp", "test-ss", "test-counted"), []string{"test-counted.close"}},
		{"NewServer right over lossy udp", lossy, mk("udp", "test-ss"), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls = nil
			if _, err := tt.engine.Server(tt.chain); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("Server() over a carrier with no plane to bind = %v, want ErrUnsupported", err)
			}
			assertCalls(t, tt.want...)
		})
	}
	calls = nil
	srv, err := e.Server(mk("udp", "test-packet-server"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-packet-server.newserver")
	assertRun(t, srv, "base.listenpacket udp 127.0.0.1:1", "test-packet-server.servepacket upstream=default")
}

func TestServerRefusesCarrierLackingARequiredPlane(t *testing.T) {
	name := fresh("test-dual-server")
	RegisterLayer(name, LayerSpec{Requires: Stream | Packet, Provides: Stream, NewServer: func(Options) (*ServerFuncs, error) {
		record("test-dual-server.newserver")
		return &ServerFuncs{Serve: failServe, ServePacket: failServePacket}, nil
	}})
	// The Base reports udp lossy, so the layer's carrier keeps only its stream.
	e := ServerEngine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	for _, tt := range []struct {
		chain Chain
		want  []string
	}{
		{mk("", name), nil},
		{mk("", name, "test-counted"), []string{"test-counted.close"}},
	} {
		calls = nil
		if _, err := e.Server(tt.chain); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Server() over a carrier lacking packet = %v, want ErrUnsupported", err)
		}
		assertCalls(t, tt.want...)
	}
}

func TestServerClosesOnce(t *testing.T) {
	calls = nil
	e := ServerEngine{Base: &closableNet{fakeNet{name: "base"}}, Upstream: &closableNet{fakeNet{name: "upstream"}}}
	tests := []struct {
		chain Chain
		want  []string
	}{
		{mk("tcp", "closableserver"), []string{"closableserver.close"}},
		{mk("tcp", "closableserver", "closable"), []string{"closableserver.close", "closable.close"}},
		{mk("tcp", "test-http", "closable"), []string{"closable.close"}},
	}
	for _, tt := range tests {
		srv, err := e.Server(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		for i := 0; i < 2; i++ {
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
		}
		assertCalls(t, tt.want...)
		if err := srv.Run(context.Background()); err != nil {
			t.Fatalf("Run() after Close = %v, want nil", err)
		}
		assertCalls(t)
	}
}
