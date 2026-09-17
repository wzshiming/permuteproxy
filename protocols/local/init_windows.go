package local

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterNetwork("pipe", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressPath, Network: pipe{Network}})
}
