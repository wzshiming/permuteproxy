// Package permuteproxy builds proxy chains from layers and networks registered by
// name; importing protocols/all registers every bundled one. The networks tcp, udp,
// unix, unixgram and cmd and the layer dgram are registered by protocols/local;
// without it a chain naming them fails with ErrInvalidChain.
//
// A Chain lists layers outermost-first over an Endpoint; ParseURI reads one from a
// URI such as socks5+tls://127.0.0.1:1080 and Chain.URI writes it back. Three
// engines each build a chain one way: TransportEngine.Transport stacks adapter layers
// into a Transport that dials and listens at the endpoint, ClientEngine.Client builds
// the client of the outermost proxy layer as a Network, which binds its own sockets
// through ClientEngine.Local and whose Listen, where the protocol has one as socks5 has
// BIND and ssh a remote forward, listens at an address on the proxy's side, and
// ServerEngine.Server builds its server, which reaches its targets through
// ServerEngine.Upstream. A chain that is only a command line, such as
// cmd:ssh -W %h:%p jump, is a client as well: each tcp dial runs the command with
// the target's host for %h and its port for %p. A carrier is on one of
// two planes: Stream, reliable ordered byte streams as tcp carries, and Packet,
// datagrams each with its peer as udp carries. A network carries one plane; a layer
// declares the planes it requires, provides and preserves, and a chain is valid
// only where they fit.
package permuteproxy
