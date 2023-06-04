package snappy

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	define := permuteproxy.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind: protocols.KindStream,
			Base: protocols.KindStream,
		},
		Handler: permuteproxy.Handler{
			DialerWrapper:       permuteproxy.DialerWrapperFunc(NewSnappyDialer),
			ListenConfigWrapper: permuteproxy.ListenConfigWrapperFunc(NewSnappyListenConfig),
		},
	}
	permuteproxy.Register("snappy", define)
}
