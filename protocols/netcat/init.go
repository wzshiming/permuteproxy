package netcat

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	// The endpoint networks: an address reached, or accepted at, by one nc per connection.
	permuteproxy.RegisterNetwork("cmd-nc", permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressHost, Dial: "cmd:" + DialTCP, Listen: "cmd:" + ListenTCP})
	// Listening goes to Network under this name, as it removes the socket file nc leaves behind.
	permuteproxy.RegisterNetwork("cmd-nc-unix", permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressPath, Dial: "cmd:" + DialUnix, Network: Network})
	// Binding goes to Network under this name too: one nc -u -l, which serves a single peer.
	permuteproxy.RegisterNetwork("cmd-nc-udp", permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressHost, Dial: "dgram+cmd:" + DialUDP, Network: Network})
	// The client: nc:[prefix] reaches each target it is asked for by an nc of its own.
	client := permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressOpaque, NewClient: NewClient}
	permuteproxy.RegisterNetwork("nc", client)
	permuteproxy.RegisterNetwork("netcat", client)
}
