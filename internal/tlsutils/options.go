package tlsutils

// User-facing URI option names; renaming one breaks existing URIs.
const (
	keySkipVerify   = "tls_skip_verify"
	keyServerName   = "tls_server_name"
	keyCAFile       = "tls_ca_file"
	keyAcmeHost     = "tls_acme_host"
	keyAcmeCacheDir = "tls_acme_cache_dir"
	keyCertFile     = "tls_cert_file"
	keyKeyFile      = "tls_key_file"
	keySelfSigned   = "tls_self_signed"
)

// ServerNameKey is the option naming the server a client verifies and asks for, which a build fills with the endpoint's host.
const ServerNameKey = keyServerName

// OptionKeys returns every tls layer option key.
func OptionKeys() []string {
	return append(OptionKeysWithoutACME(), keyAcmeHost, keyAcmeCacheDir)
}

// OptionKeysWithoutACME returns the option keys minus the ACME ones, for carriers ACME's tls-alpn-01 challenge cannot reach.
func OptionKeysWithoutACME() []string {
	return []string{keySkipVerify, keyServerName, keyCAFile, keyCertFile, keyKeyFile, keySelfSigned}
}
