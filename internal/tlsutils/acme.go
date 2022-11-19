package tlsutils

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/wzshiming/hostmatcher"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func NewAcme(hosts []string, dir string) *tls.Config {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
	}
	if len(hosts) > 0 {
		matcher := hostmatcher.NewMatcher(hosts)
		m.HostPolicy = func(ctx context.Context, host string) error {
			if !matcher.Match(host) {
				return fmt.Errorf("not allow host %q", host)
			}
			return nil
		}
	}
	if dir == "" {
		dir = cacheDir()
	}
	m.Cache = autocert.DirCache(dir)
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos: []string{
			acme.ALPNProto, // enable tls-alpn ACME challenges
		},
	}
}

func homeDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/"
}

func cacheDir() string {
	const base = "autocert"
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir(), "Library", "Caches", base)
	case "windows":
		for _, ev := range []string{"APPDATA", "CSIDL_APPDATA", "TEMP", "TMP"} {
			if v := os.Getenv(ev); v != "" {
				return filepath.Join(v, base)
			}
		}
		// Worst case:
		return filepath.Join(homeDir(), base)
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, base)
	}
	return filepath.Join(homeDir(), ".cache", base)
}
