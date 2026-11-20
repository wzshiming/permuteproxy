package snappy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("snappy", permuteproxy.Spec{
		Kind:       permuteproxy.KindAdapter,
		Requires:   permuteproxy.Stream,
		Provides:   permuteproxy.Stream,
		NewAdapter: NewAdapter,
	})
}
