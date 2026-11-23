package quic

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func init() {
	permuteproxy.RegisterLayer("quic", permuteproxy.LayerSpec{
		Kind:       permuteproxy.LayerAdapter,
		Requires:   permuteproxy.Packet,
		Provides:   permuteproxy.Stream,
		Options:    tlsutils.OptionKeysWithoutAcme(),
		NewAdapter: NewAdapter,
	})
}
