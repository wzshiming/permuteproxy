package tls

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("tls", permuteproxy.Spec{
		Kind:     permuteproxy.KindAdapter,
		Requires: permuteproxy.Stream,
		Provides: permuteproxy.Stream,
		Options:  options,
		Adapt:    Adapt,
	})
	permuteproxy.RegisterAlias("https", "http+tls")
}
