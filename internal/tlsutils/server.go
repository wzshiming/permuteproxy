package tlsutils

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func NewServer(metadata url.Values) (*tls.Config, error) {
	if metadata.Has("tls_acme_host") {
		hosts := strings.Split(strings.Join(metadata["tls_acme_host"], ","), ",")
		cacheDir := metadata.Get("tls_acme_cache_dir")
		return NewAcme(hosts, cacheDir), nil
	} else if certFile, keyFile := metadata.Get("tls_cert_file"), metadata.Get("tls_key_file"); certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(metadata.Get("tls_cert_file"), metadata.Get("tls_key_file"))
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	} else if selfSigned, _ := strconv.ParseBool(metadata.Get("tls_self_signed")); selfSigned {
		return NewSelfSigned()
	}
	return nil, fmt.Errorf("can't new tls.Config for server")
}
