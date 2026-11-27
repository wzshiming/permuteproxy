package tlsutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// selfSignedLife is how long a self-signed certificate stays valid, longer than a listener is expected to run.
const selfSignedLife = 10 * 365 * 24 * time.Hour

// NewSelfSigned makes a config serving a fresh certificate that no CA vouches for, valid from now on.
func NewSelfSigned() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	// The hour before now admits a peer whose clock runs behind.
	notBefore := time.Now().Add(-time.Hour)
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(selfSignedLife),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certDER},
				PrivateKey:  key,
			},
		},
	}, nil
}
