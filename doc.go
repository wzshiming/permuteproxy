// Package permuteproxy builds proxy chains from layers and networks registered by
// name; importing protocols/all registers every bundled one.
//
// A Chain lists layers outermost-first over an Endpoint; ParseURI reads one from a
// URI such as socks5+tls://127.0.0.1:1080 and Chain.URI writes it back. An Engine
// builds a chain at three entry points: Engine.Transport stacks adapter layers into
// a Transport that dials and listens at the endpoint, Engine.Client builds the
// client of the outermost proxy layer as a Network, and Engine.Server builds its
// server, which reaches its targets through Engine.Upstream.
//
// A carrier is on one of two planes: Stream, reliable ordered byte streams as tcp
// carries, and Packet, datagrams each with its peer as udp carries. A network
// carries one plane; a layer declares the planes it requires, provides and
// preserves, and a chain is valid only where they fit.
package permuteproxy
