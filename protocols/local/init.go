package local

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
)

func init() {
	permuteproxy.ImplementNetwork("cmd", Network)
	permuteproxy.RegisterNetwork("cmd-nc", permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressHost, Dial: "cmd:" + cmdutils.NetcatDialTCP, Listen: "cmd:" + cmdutils.NetcatListenTCP})
	// Listening goes to Local under this name, as it removes the socket file nc leaves behind.
	permuteproxy.RegisterNetwork("cmd-nc-unix", permuteproxy.NetworkSpec{AddressKind: permuteproxy.AddressPath, Dial: "cmd:" + cmdutils.NetcatDialUnix, Network: Network})
}
