package shadowsocks

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
			PasswordField: KeyPassword,
		},
		Handler: permuteproxy.Handler{
			DialerWrapper: permuteproxy.DialerWrapperFunc(NewShadowsocksDialer),
			NewRunner:     permuteproxy.NewRunnerFunc(NewShadowsocksRunner),
		},
	}
	permuteproxy.Registry("shadowsocks", define)
	permuteproxy.Registry("ss", define)
}
