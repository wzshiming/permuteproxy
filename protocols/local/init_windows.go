package local

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	metas := map[string]permuteproxy.Define{
		"pipe": {
			Handler: permuteproxy.Handler{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressPath,
			},
		},
	}
	for scheme, meta := range metas {
		protocols.Register(scheme, meta)
	}
}
