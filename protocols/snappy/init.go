package snappy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("snappy", permuteproxy.LayerSpec{
		Kind:       permuteproxy.LayerAdapter,
		Requires:   permuteproxy.Stream,
		Provides:   permuteproxy.Stream,
		NewAdapter: NewAdapter,
	})
}
