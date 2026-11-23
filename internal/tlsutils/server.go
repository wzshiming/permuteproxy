package tlsutils

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func NewServer(metadata url.Values) (*tls.Config, error) {
	if metadata.Has(keyAcmeHost) {
		hosts := strings.Split(strings.Join(metadata[keyAcmeHost], ","), ",")
		cacheDir := metadata.Get(keyAcmeCacheDir)
		return NewAcme(hosts, cacheDir), nil
	} else if certFile, keyFile := metadata.Get(keyCertFile), metadata.Get(keyKeyFile); certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(metadata.Get(keyCertFile), metadata.Get(keyKeyFile))
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	} else if selfSigned, _ := strconv.ParseBool(metadata.Get(keySelfSigned)); selfSigned {
		return NewSelfSigned()
	}
	return nil, fmt.Errorf("can't new tls.Config for server")
}
