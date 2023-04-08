package socks4

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	define := permuteproxy.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind:          protocols.KindProxy,
			Base:          protocols.KindStream,
			UsernameField: KeyUsername,
		},
		Handler: permuteproxy.Handler{
			DialerWrapper: permuteproxy.DialerWrapperFunc(NewSocks4Dialer),
			NewRunner:     permuteproxy.NewRunnerFunc(NewSocks4Runner),
		},
	}
	permuteproxy.Registry("socks4", define)
	permuteproxy.Registry("socks4s", define)
}
