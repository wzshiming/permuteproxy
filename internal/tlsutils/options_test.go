package tlsutils

import (
	"slices"
	"testing"
)

var (
	acmeKeys  = []string{"tls_acme_host", "tls_acme_cache_dir"}
	otherKeys = []string{"tls_skip_verify", "tls_server_name", "tls_ca_file", "tls_cert_file", "tls_key_file", "tls_self_signed"}
)

func sorted(keys []string) []string {
	return slices.Sorted(slices.Values(keys))
}

func TestOptionKeysWithoutACMEHoldTheNonAcmeKeys(t *testing.T) {
	if got, want := sorted(OptionKeysWithoutACME()), sorted(otherKeys); !slices.Equal(got, want) {
		t.Fatalf("OptionKeysWithoutAcme() = %q, want %q", got, want)
	}
}

func TestOptionKeysAddTheAcmeKeys(t *testing.T) {
	if got, want := sorted(OptionKeys()), sorted(slices.Concat(otherKeys, acmeKeys)); !slices.Equal(got, want) {
		t.Fatalf("OptionKeys() = %q, want %q", got, want)
	}
}
