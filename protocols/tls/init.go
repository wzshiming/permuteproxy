package tls

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	define := permuteproxy.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind: protocols.KindStream,
			Base: protocols.KindStream,
			MetaFields: []string{
				"tls_skip_verify",
				"tls_acme_host",
				"tls_acme_cache_dir",
				"tls_cert_file",
				"tls_key_file",
				"tls_self_signed",
			},
		},
		Handler: permuteproxy.Handler{
			DialerWrapper:       permuteproxy.DialerWrapperFunc(NewTLSDialer),
			ListenConfigWrapper: permuteproxy.ListenConfigWrapperFunc(NewTLSListenConfig),
		},
	}
	permuteproxy.Register("tls", define)
	protocols.RegisterAlias("http+tls", "https")
	protocols.RegisterReverseAlias("http+tls", "https")
}
