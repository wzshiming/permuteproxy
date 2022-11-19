package sshproxy

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
			MetaFields: []string{
				"identity_data",
				"identity_file",
				"authorized_data",
				"authorized_file",
				"hostkey_data",
				"hostkey_file",
			},
			DialSupport: []string{
				"tcp",
			},
		},
		Handler: permuteproxy.Handler{
			DialerWrapper: permuteproxy.DialerWrapperFunc(NewSSHProxyDialer),
			NewRunner:     permuteproxy.NewRunnerFunc(NewSSHProxyRunner),
		},
	}
	permuteproxy.Registry("ssh", define)
}
