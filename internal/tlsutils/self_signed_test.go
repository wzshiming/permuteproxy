package tlsutils

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewSelfSignedIsValidNow(t *testing.T) {
	config, err := NewSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		t.Fatalf("certificate valid from %v to %v, which leaves out now", cert.NotBefore, cert.NotAfter)
	}
	if _, ok := config.Certificates[0].PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("private key is %T, want *ecdsa.PrivateKey", config.Certificates[0].PrivateKey)
	}
	// A client pinning the certificate as its only root verifies the chain.
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("certificate does not verify against itself: %v", err)
	}
}

func TestNewSelfSignedSerialsDiffer(t *testing.T) {
	serial := func() string {
		config, err := NewSelfSigned()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return cert.SerialNumber.String()
	}
	if a, b := serial(), serial(); a == b {
		t.Fatalf("two certificates share the serial %s", a)
	}
}
