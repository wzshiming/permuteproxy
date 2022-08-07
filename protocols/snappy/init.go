package snappy

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	protocols.Registry("snappy", protocols.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind: protocols.KindStream,
			Base: protocols.KindStream,
		},
		Handle: protocols.Handle{
			DialerWrapper:       protocols.DialerWrapperFunc(NewSnappyDialer),
			ListenConfigWrapper: protocols.ListenConfigWrapperFunc(NewSnappyListenConfig),
		},
	})
}
