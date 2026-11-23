package tls

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func init() {
	permuteproxy.RegisterLayer("tls", permuteproxy.LayerSpec{
		Kind:       permuteproxy.LayerAdapter,
		Requires:   permuteproxy.Stream,
		Provides:   permuteproxy.Stream,
		OptionKeys: tlsutils.OptionKeys(),
		NewAdapter: NewAdapter,
	})
	permuteproxy.RegisterAlias("https", "http+tls")
}
