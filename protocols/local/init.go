package local

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterNetwork("tcp", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressHost, Network: Network})
	permuteproxy.RegisterNetwork("udp", permuteproxy.NetworkSpec{Plane: permuteproxy.Packet, AddressKind: permuteproxy.AddressHost, Network: Network})
	permuteproxy.RegisterNetwork("unix", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressPath, Network: Network})
	permuteproxy.RegisterNetwork("unixgram", permuteproxy.NetworkSpec{Plane: permuteproxy.Packet, AddressKind: permuteproxy.AddressPath, Network: Network})
}
