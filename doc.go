// Package permuteproxy builds proxy chains from layers and networks registered by
// name; importing protocols/all registers every bundled one. The package registers none
// itself: tcp, udp, unix and unixgram come from protocols/local and cmd from
// protocols/command, and without them a chain naming one fails with ErrInvalidChain.
//
// A Chain lists layers outermost-first over an Endpoint; ParseURI reads one from a
// URI such as socks5+tls://127.0.0.1:1080 and Chain.URI writes it back. A carrier is
// on one of two planes: Stream, reliable ordered byte streams as tcp carries, and
// Packet, datagrams each with its peer as udp carries. A network carries one plane; a
// layer declares the planes it requires, provides and preserves, and a chain is valid
// only where they fit.
//
// Three engines each build a chain one way. TransportEngine.Transport stacks adapter
// layers into a Transport that dials and listens at the endpoint. ClientEngine.Client
// builds the client of the outermost proxy layer as a Network, which binds its own
// sockets through ClientEngine.Local and whose Listen, where the protocol has one as
// socks5 has BIND and ssh a remote forward, listens at an address on the proxy's side.
// ServerEngine.Server builds its server, which reaches its targets through
// ServerEngine.Upstream. A chain of one network that declares NetworkSpec.NewClient is a
// client as well, as the command lines cmd:ssh -W %h:%p jump of protocols/command and
// nc:ssh jump of protocols/netcat are.
//
// NewClient, NewServer and ListenAndServe build a proxy chain straight from its URI
// with the zero engines, for a caller that injects no network of its own.
package permuteproxy
