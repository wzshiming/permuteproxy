package quic

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func init() {
	permuteproxy.RegisterLayer("quic", permuteproxy.LayerSpec{
		Requires:   permuteproxy.Packet,
		Provides:   permuteproxy.Stream,
		OptionKeys: tlsutils.OptionKeysWithoutACME(),
		HostKey:    tlsutils.ServerNameKey,
		NewAdapter: NewAdapter,
	})
}
