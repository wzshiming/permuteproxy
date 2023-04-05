package anyproxy

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
			DialSupport: []string{
				"tcp",
			},
		},
		Handler: permuteproxy.Handler{
			NewRunner: permuteproxy.NewRunnerFunc(NewAnyProxyRunner),
		},
	}
	permuteproxy.Registry("any", define)
}
