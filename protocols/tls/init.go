package tls

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func init() {
	permuteproxy.RegisterLayer("tls", permuteproxy.Spec{
		Kind:     permuteproxy.KindAdapter,
		Requires: permuteproxy.Stream,
		Provides: permuteproxy.Stream,
		Options:  tlsutils.OptionKeys(),
		Adapt:    Adapt,
	})
	permuteproxy.RegisterAlias("https", "http+tls")
}
