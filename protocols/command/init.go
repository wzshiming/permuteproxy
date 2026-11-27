package command

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	// The network: its address is a command line, and alone it is the client that fills the line per target.
	spec := permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressOpaque, Network: Network, NewClient: NewClient}
	permuteproxy.RegisterNetwork("cmd", spec)
	permuteproxy.RegisterNetwork("command", spec)
	permuteproxy.RegisterLayer("dgram", dgram)
	// The address is the whole command line, such as ssh host nc -u 1.1.1.1 53 or a socat invocation.
	packet := permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressOpaque, Dial: "dgram+cmd:%a"}
	permuteproxy.RegisterNetwork("cmd-packet", packet)
	permuteproxy.RegisterNetwork("command-packet", packet)
}
