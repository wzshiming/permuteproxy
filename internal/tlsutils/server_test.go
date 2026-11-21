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
