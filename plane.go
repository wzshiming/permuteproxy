package permuteproxy

import (
	"strings"
)

// Plane is a set of the kinds of carrier a transport offers: byte streams, datagrams or both.
type Plane uint8

const (
	Stream Plane = 1 << iota // reliable ordered byte streams, as tcp carries
	Packet                   // datagrams each with its peer, as udp carries
)

// String names the planes in p joined by '|', or "none".
func (p Plane) String() string {
	var names []string
	if p&Stream != 0 {
		names = append(names, "stream")
	}
	if p&Packet != 0 {
		names = append(names, "packet")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}
