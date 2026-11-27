package local

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterNetwork("tcp", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressHost, Network: Network})
	permuteproxy.RegisterNetwork("udp", permuteproxy.NetworkSpec{Plane: permuteproxy.Packet, AddressKind: permuteproxy.AddressHost, Network: Network})
	permuteproxy.RegisterNetwork("unix", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressPath, Network: Network})
	permuteproxy.RegisterNetwork("unixgram", permuteproxy.NetworkSpec{Plane: permuteproxy.Packet, AddressKind: permuteproxy.AddressPath, Network: Network})
	permuteproxy.RegisterNetwork("cmd", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressOpaque, Network: Network})
	permuteproxy.RegisterLayer("dgram", dgram)
	// The address is the whole command line, such as ssh host nc -u 1.1.1.1 53 or a socat invocation.
	permuteproxy.RegisterNetwork("cmd-packet", permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressOpaque, Dial: "dgram+cmd:%a"})
}
