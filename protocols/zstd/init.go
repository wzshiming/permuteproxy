package zstd

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("zstd", permuteproxy.LayerSpec{
		Requires:   permuteproxy.Stream,
		Provides:   permuteproxy.Stream,
		NewAdapter: NewAdapter,
	})
}
