package tlsutils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strconv"
)

func NewClient(metadata url.Values) (*tls.Config, error) {
	config := &tls.Config{ServerName: metadata.Get("tls_server_name")}
	if skipVerify, _ := strconv.ParseBool(metadata.Get("tls_skip_verify")); skipVerify {
		config.InsecureSkipVerify = true
		return config, nil
	}
	if caFile := metadata.Get("tls_ca_file"); caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
		return config, nil
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	config.RootCAs = certPool
	return config, nil
}
