package tlsutils

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strconv"
)

func NewClient(metadata url.Values) (*tls.Config, error) {
	if skipVerify, _ := strconv.ParseBool(metadata.Get("tls_skip_verify")); skipVerify {
		return &tls.Config{
			InsecureSkipVerify: true,
		}, nil
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs: certPool,
	}, nil
}
