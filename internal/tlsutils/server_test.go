package tlsutils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestNewServerTurnsToAcmeOnAcmeHost(t *testing.T) {
	config, err := NewServer(url.Values{"tls_acme_host": {"proxy.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(config.NextProtos, []string{acme.ALPNProto}) {
		t.Fatalf("NextProtos = %q, want the ACME tls-alpn-01 protocol", config.NextProtos)
	}
}

func TestNewServerReadsAcmeCertificatesFromCacheDir(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"proxy.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	entry := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	// The tls-alpn-01 challenge path reads autocert's "<host>+token" entry without host policy or network.
	if err := os.WriteFile(filepath.Join(dir, "proxy.test+token"), entry, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := NewServer(url.Values{"tls_acme_host": {"proxy.test"}, "tls_acme_cache_dir": {dir}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "proxy.test", SupportedProtos: []string{acme.ALPNProto}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Certificate[0], certDER) {
		t.Fatal("served certificate is not the one cached in tls_acme_cache_dir")
	}
}

func TestNewServerACMEHostPolicy(t *testing.T) {
	for _, tt := range []struct {
		name, hosts, host string
		admitted          bool
	}{
		{"a listed name passes", "proxy.test", "proxy.test", true},
		{"an unlisted name is refused", "proxy.test", "other.test", false},
		{"a subdomain of a listed name is refused", "proxy.test", "www.proxy.test", false},
		{"a star admits any name", "*", "any.test", true},
		{"a listed name is trimmed of blanks", "other.test, proxy.test ", "proxy.test", true},
		{"a star among names admits any name", "proxy.test, *", "any.test", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// An unusable account key stops an admitted name before autocert contacts the CA.
			if err := os.WriteFile(filepath.Join(dir, "acme_account+key"), []byte("unusable"), 0o600); err != nil {
				t.Fatal(err)
			}
			config, err := NewServer(url.Values{"tls_acme_host": {tt.hosts}, "tls_acme_cache_dir": {dir}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = config.GetCertificate(&tls.ClientHelloInfo{ServerName: tt.host})
			if err == nil || strings.Contains(err.Error(), "invalid account key") != tt.admitted {
				t.Fatalf("GetCertificate(%q) with tls_acme_host=%q: %v; want it past the host policy: %t", tt.host, tt.hosts, err, tt.admitted)
			}
		})
	}
}
