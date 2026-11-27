package permuteproxy

import (
	"testing"
)

func init() {
	ported := fakeProxy("test-ported", Stream, Stream, 0, "username", "password")
	ported.DefaultPort = "1080"
	RegisterLayer("test-ported", ported)
	RegisterAlias("test-porteds", AliasSpec{Expansion: "test-ported+test-tls", DefaultPort: "8443"})
	RegisterAlias("test-plain", AliasSpec{Expansion: "test-ported+test-snappy"})
}

func TestEndpointTakesTheDefaultPort(t *testing.T) {
	tests := []struct {
		uri, want string
	}{
		{"test-ported://proxy.test", "proxy.test:1080"},
		{"test-ported://proxy.test:", "proxy.test:1080"},
		{"test-ported://proxy.test:9", "proxy.test:9"},
		{"test-ported://user:pass@proxy.test", "proxy.test:1080"},
		{"test-ported://[::1]", "[::1]:1080"},
		{"test-ported://[::1]:9", "[::1]:9"},
		{"test-ported://[fe80::1%25eth0]", "[fe80::1%eth0]:1080"},
		{"test-ported+tcp://proxy.test", "proxy.test:1080"},
		{"test-ported+test-snappy://proxy.test", "proxy.test:1080"},
		// An alias that declares a port goes ahead of its outermost layer, written folded or not.
		{"test-porteds://proxy.test", "proxy.test:8443"},
		{"test-ported+test-tls://proxy.test", "proxy.test:8443"},
		{"test-porteds://proxy.test:9", "proxy.test:9"},
		{"test-plain://proxy.test", "proxy.test:1080"},
		// The tokens do not open with the alias's expansion, so the layer's port holds.
		{"test-ported+test-snappy+test-tls://proxy.test", "proxy.test:1080"},
		// A path is no host:port address, and a layer without a default leaves the address alone.
		{"test-ported+unix:///run/proxy.sock", "/run/proxy.sock"},
		{"test-http://proxy.test", "proxy.test"},
		{"test-tls://proxy.test", "proxy.test"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			c, err := ParseURI(tt.uri)
			if err != nil {
				t.Fatal(err)
			}
			r, err := c.resolve()
			if err != nil {
				t.Fatal(err)
			}
			if r.dial != tt.want || r.listen != tt.want {
				t.Fatalf("dial %q, listen %q, want %q", r.dial, r.listen, tt.want)
			}
		})
	}
}

// The port is filled per build, so a chain keeps the address it was written with.
func TestDefaultPortStaysOutOfTheURI(t *testing.T) {
	for _, uri := range []string{"test-ported://proxy.test", "test-porteds://[::1]"} {
		c, err := ParseURI(uri)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.URI(); err != nil || got != uri {
			t.Fatalf("URI() = %q, %v, want %q", got, err, uri)
		}
	}
}

// The host a layer's HostKey takes is read after the port is filled.
func TestDefaultPortKeepsTheEndpointHost(t *testing.T) {
	c, err := ParseURI("test-porteds://proxy.test")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if r.host != "proxy.test" {
		t.Fatalf("host = %q, want proxy.test", r.host)
	}
}

func TestWithPort(t *testing.T) {
	tests := []struct {
		address, want string
	}{
		{"", ""},
		{"host", "host:22"},
		{"host:", "host:22"},
		{"host:1", "host:1"},
		{":1", ":1"},
		{"::1", "[::1]:22"},
		{"[::1]", "[::1]:22"},
		{"[::1]:", "[::1]:22"},
		{"fe80::1%eth0", "[fe80::1%eth0]:22"},
		{"a:b:c", "a:b:c"},
		{"[host", "[host"},
	}
	for _, tt := range tests {
		if got := withPort(tt.address, "22"); got != tt.want {
			t.Errorf("withPort(%q) = %q, want %q", tt.address, got, tt.want)
		}
	}
	if got := withPort("host", ""); got != "host" {
		t.Errorf("withPort without a port = %q, want host", got)
	}
}

func TestRegisterRejectsAMalformedDefaultPort(t *testing.T) {
	for _, port := range []string{"0", "65536", "-1", "ssh", "080", " 80"} {
		mustPanic(t, "layer port "+port, func() {
			spec := fakeProxy("x", Stream, Stream, 0, "", "")
			spec.DefaultPort = port
			RegisterLayer(fresh("bad-port"), spec)
		})
		mustPanic(t, "alias port "+port, func() {
			RegisterAlias(fresh("bad-port"), AliasSpec{Expansion: "test-http+test-tls", DefaultPort: port})
		})
	}
}
