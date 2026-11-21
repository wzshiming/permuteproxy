package local

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	// The default network resolves each call by its name, so this one is only asked for pipe.
	permuteproxy.RegisterNetwork("pipe", permuteproxy.NetworkSpec{Plane: permuteproxy.Stream, AddressKind: permuteproxy.AddressPath, Network: permuteproxy.NetworkFuncs{DialContextFunc: dialPipe, ListenFunc: listenPipe}})
}
