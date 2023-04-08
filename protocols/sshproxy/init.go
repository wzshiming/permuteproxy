package sshproxy

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	metas := map[string]permuteproxy.Define{
		"ssh": {
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
			},
			Handler: permuteproxy.Handler{
				DialerWrapper: permuteproxy.DialerWrapperFunc(NewSSHProxyDialer),
				NewRunner:     permuteproxy.NewRunnerFunc(NewSSHProxyRunner),
			},
		},
		"ssh-cmd": {
			SchemeInfo: protocols.SchemeInfo{
				Kind:          protocols.KindProxy,
				Base:          protocols.KindStream,
				UsernameField: KeyUsername,
				PasswordField: KeyPassword,
				MetaFields: []string{
					"identity_data",
					"identity_file",
				},
			},
			Handler: permuteproxy.Handler{
				DialerWrapper: permuteproxy.DialerWrapperFunc(NewSSHProxyCommandDialer),
			},
		},
		"ssh-cmd-nc": {
			SchemeInfo: protocols.SchemeInfo{
				Kind:          protocols.KindProxy,
				Base:          protocols.KindStream,
				UsernameField: KeyUsername,
				PasswordField: KeyPassword,
				MetaFields: []string{
					"identity_data",
					"identity_file",
				},
			},
			Handler: permuteproxy.Handler{
				DialerWrapper: permuteproxy.DialerWrapperFunc(NewSSHProxyCommandNetCatDialer),
			},
		},
		"ssh-cmd-nc-unix": {
			SchemeInfo: protocols.SchemeInfo{
				Kind:          protocols.KindProxy,
				Base:          protocols.KindStream,
				UsernameField: KeyUsername,
				PasswordField: KeyPassword,
				MetaFields: []string{
					"identity_data",
					"identity_file",
				},
			},
			Handler: permuteproxy.Handler{
				DialerWrapper: permuteproxy.DialerWrapperFunc(NewSSHProxyCommandNetCatUnixDialer),
			},
		},
	}
	for scheme, meta := range metas {
		permuteproxy.Registry(scheme, meta)
	}
}
