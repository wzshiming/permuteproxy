package tlsutils

// User-facing URI option names; renaming one breaks existing URIs.
const (
	KeySkipVerify   = "tls_skip_verify"
	KeyServerName   = "tls_server_name"
	KeyCAFile       = "tls_ca_file"
	KeyAcmeHost     = "tls_acme_host"
	KeyAcmeCacheDir = "tls_acme_cache_dir"
	KeyCertFile     = "tls_cert_file"
	KeyKeyFile      = "tls_key_file"
	KeySelfSigned   = "tls_self_signed"
)

// OptionKeys returns every tls layer option key.
func OptionKeys() []string {
	return append(OptionKeysWithoutACME(), KeyAcmeHost, KeyAcmeCacheDir)
}

// OptionKeysWithoutACME returns the option keys minus the ACME ones, for carriers ACME's tls-alpn-01 challenge cannot reach.
func OptionKeysWithoutACME() []string {
	return []string{KeySkipVerify, KeyServerName, KeyCAFile, KeyCertFile, KeyKeyFile, KeySelfSigned}
}
