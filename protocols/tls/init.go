package tls

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func init() {
	permuteproxy.RegisterLayer("tls", permuteproxy.LayerSpec{
		Kind:       permuteproxy.KindAdapter,
		Requires:   permuteproxy.Stream,
		Provides:   permuteproxy.Stream,
		Options:    tlsutils.OptionKeys(),
		NewAdapter: NewAdapter,
	})
	permuteproxy.RegisterAlias("https", "http+tls")
}
