package socks5

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
			DialerWrapper: permuteproxy.DialerWrapperFunc(NewSocks5Dialer),
			NewRunner:     permuteproxy.NewRunnerFunc(NewSocks5Runner),
		},
	}
	permuteproxy.Register("socks5", define)
	permuteproxy.Register("socks5h", define)
}
