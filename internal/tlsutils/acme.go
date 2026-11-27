package tlsutils

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func NewACME(hosts []string, dir string) *tls.Config {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
	}
	if len(hosts) > 0 {
		names := make([]string, len(hosts))
		for i, host := range hosts {
			names[i] = strings.TrimSpace(host)
		}
		if !slices.Contains(names, "*") {
			m.HostPolicy = autocert.HostWhitelist(names...)
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
