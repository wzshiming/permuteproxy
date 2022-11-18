package ssh

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	protocols.Registry("ssh", protocols.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind:          protocols.KindProxy,
			Base:          protocols.KindStream,
			UsernameField: "username",
			PasswordField: "password",
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
		Handle: protocols.Handle{
			NewDialerFunc: NewSSHDialer,
			NewRunnerFunc: NewSSHRunner,
		},
	})
}
