package protoutils

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/serverutils"
)

// Server is the lifecycle NewServer and NewPlaneServer return.
type Server = serverutils.Server

// NewServer serves one listener, whose accepted connections are closed along with it.
func NewServer(listen func(ctx context.Context) (net.Listener, error), serve func(ctx context.Context, ln net.Listener) error) *Server {
	return serverutils.NewServer(listen, serve)
}

// NewPlaneServer binds a listener for Stream and a packet conn for Packet, as inner declares,
// before serving either; a failed bind releases what was bound and the first serve to return
// stops the other and decides the result.
func NewPlaneServer(inner permuteproxy.Transport, serveStream func(ctx context.Context, ln net.Listener) error, servePacket func(ctx context.Context, pc net.PacketConn) error) *Server {
	var listen func(ctx context.Context) (net.Listener, error)
	var listenPacket func(ctx context.Context) (net.PacketConn, error)
	planes := inner.Planes()
	if planes&permuteproxy.Stream != 0 {
		listen = inner.Listen
	}
	if planes&permuteproxy.Packet != 0 {
		listenPacket = inner.ListenPacket
	}
	return serverutils.NewPlaneServer(listen, listenPacket, serveStream, servePacket)
}
