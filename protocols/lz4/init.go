package lz4

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("lz4", permuteproxy.LayerSpec{
		Requires:   permuteproxy.Stream,
		Provides:   permuteproxy.Stream,
		NewAdapter: NewAdapter,
	})
}
