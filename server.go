package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy/internal/serverutils"
)

// ServerFuncs declares a proxy's server; the root package binds the carriers it serves and runs them.
type ServerFuncs struct {
	Serve       func(ctx context.Context, ln net.Listener, upstream Network) error   // serves the Stream carrier until it fails or ctx ends
	ServePacket func(ctx context.Context, pc net.PacketConn, upstream Network) error // serves the Packet carrier until it fails or ctx ends
	Close       func() error                                                         // optional; releases what NewServer acquired, and may run while Serve or ServePacket are still returning
}

// server builds over inner the server s.NewServer declares, reaching its targets through upstream.
func (s LayerSpec) server(inner Transport, upstream Network, opts Options) (Server, error) {
	funcs, err := s.NewServer(opts)
	switch {
	case err != nil:
		return nil, invalid(err)
	case funcs == nil:
		return nil, fmt.Errorf("NewServer returned nil: %w", ErrInvalidChain)
	case funcs.Serve == nil && (s.Requires|s.Preserves)&Stream != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no Serve for %v", Stream))
	case funcs.ServePacket == nil && (s.Requires|s.Preserves)&Packet != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no ServePacket for %v", Packet))
	}
	var listen func(context.Context) (net.Listener, error)
	var listenPacket func(context.Context) (net.PacketConn, error)
	planes := inner.Planes() & (s.Requires | s.Preserves)
	if planes&Stream != 0 {
		listen = inner.Listen
	}
	if planes&Packet != 0 {
		listenPacket = inner.ListenPacket
	}
	srv := serverutils.NewServer(listen, listenPacket,
		func(ctx context.Context, ln net.Listener) error { return funcs.Serve(ctx, ln, upstream) },
		func(ctx context.Context, pc net.PacketConn) error { return funcs.ServePacket(ctx, pc, upstream) },
	)
	return assembledServer{srv, closeOnce(funcs.Close, inner)}, nil
}

// assembledServer is a declared server; the engine built its inner Transport, so Close releases it too.
type assembledServer struct {
	*serverutils.Server
	close func() error
}

// Close stops the server as the lifecycle does, then releases it and its inner Transport once.
func (a assembledServer) Close() error {
	return errors.Join(a.Server.Close(), a.close())
}
