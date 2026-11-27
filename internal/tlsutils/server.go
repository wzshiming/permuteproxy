package tlsutils

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func NewServer(metadata url.Values) (*tls.Config, error) {
	if metadata.Has(KeyAcmeHost) {
		hosts := strings.Split(strings.Join(metadata[KeyAcmeHost], ","), ",")
		cacheDir := metadata.Get(KeyAcmeCacheDir)
		return NewACME(hosts, cacheDir), nil
	} else if certFile, keyFile := metadata.Get(KeyCertFile), metadata.Get(KeyKeyFile); certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(metadata.Get(KeyCertFile), metadata.Get(KeyKeyFile))
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	} else if selfSigned, _ := strconv.ParseBool(metadata.Get(KeySelfSigned)); selfSigned {
		return NewSelfSigned()
	}
	return nil, fmt.Errorf("can't new tls.Config for server")
}
