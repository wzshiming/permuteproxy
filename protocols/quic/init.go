package quic

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func init() {
	permuteproxy.RegisterLayer("quic", permuteproxy.Spec{
		Kind:       permuteproxy.KindAdapter,
		Requires:   permuteproxy.Packet,
		Provides:   permuteproxy.Stream,
		Options:    tlsutils.OptionKeysWithoutAcme(),
		NewAdapter: NewAdapter,
	})
}
