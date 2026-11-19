package local

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.ImplementNetwork("cmd", Network)
	permuteproxy.RegisterNetwork("cmd-nc", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressHost, Network: Network})
	permuteproxy.RegisterNetwork("cmd-nc-unix", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressPath, Network: Network})
}
