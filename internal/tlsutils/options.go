package tlsutils

// OptionKeys returns every tls layer option key.
func OptionKeys() []string {
	return append(OptionKeysWithoutAcme(), "tls_acme_host", "tls_acme_cache_dir")
}

// OptionKeysWithoutAcme returns the option keys minus the ACME ones, for carriers ACME's tls-alpn-01 challenge cannot reach.
func OptionKeysWithoutAcme() []string {
	return []string{"tls_skip_verify", "tls_server_name", "tls_ca_file", "tls_cert_file", "tls_key_file", "tls_self_signed"}
}
