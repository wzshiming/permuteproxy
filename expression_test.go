package permuteproxy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// The expression fixtures are registered after chain_test.go's, so they may name its layers and networks.
func init() {
	RegisterNetwork("test-nc", NetworkSpec{AddressKind: AddressHost, Dial: "cmd:nc %h %p", Listen: "cmd:nc -l %h %p"})
	RegisterNetwork("test-nc-unix", NetworkSpec{AddressKind: AddressPath, Dial: "cmd:nc -U %h", Network: &fakeNet{name: "impl"}})
	RegisterNetwork("test-nc-udp", NetworkSpec{AddressKind: AddressHost, Dial: "dgram+cmd:nc -u -w 30 %h %p"})
	RegisterNetwork("test-cmd-packet", NetworkSpec{AddressKind: AddressOpaque, Dial: "dgram+cmd:%a"})
}

func TestRegisterNetworkDerivesPlaneFromDial(t *testing.T) {
	for name, want := range map[string]Plane{
		"test-nc":         Stream,
		"test-nc-unix":    Stream,
		"test-nc-udp":     Packet,
		"test-cmd-packet": Packet,
	} {
		if ns, ok := lookupNetwork(name); !ok || ns.Plane != want {
			t.Fatalf("%s: registered %v with plane %v, want %v", name, ok, ns.Plane, want)
		}
	}
}

// panicked runs f and returns what it panicked with, or "" when it returned.
func panicked(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func TestRegisterNetworkRejectsExpressions(t *testing.T) {
	host := func(dial, listen string) NetworkSpec {
		return NetworkSpec{AddressKind: AddressHost, Dial: dial, Listen: listen}
	}
	tests := []struct {
		name string
		spec NetworkSpec
		want string // what the panic names
	}{
		{"no scheme", host("nc %h %p", ""), "unparsable"},
		{"empty scheme", host(":nc %h %p", ""), "unparsable"},
		{"empty layer", host("+cmd:nc %h %p", ""), "unparsable"},
		{"malformed token", host("Cmd:nc %h %p", ""), "unparsable"},
		{"empty template", host("cmd:", ""), "unparsable"},
		{"query in template", host("cmd:nc %h %p?x", ""), "unparsable"},
		{"fragment in template", host("cmd:nc %h#%p", ""), "unparsable"},
		{"control character in template", host("cmd:nc\t%h %p", ""), "unparsable"},
		{"opaque template read as a path", host("cmd:/bin/nc %h %p", ""), "unparsable"},
		{"authority over an opaque network", host("cmd://nc %h %p", ""), "unparsable"},
		{"opaque over a host network", host("tcp:%h:%p", ""), "unparsable"},
		{"unknown layer", host("bogus+cmd:nc %h %p", ""), `"bogus" is not a registered adapter`},
		{"proxy layer", host("test-http+cmd:nc %h %p", ""), `"test-http" is not a registered adapter`},
		{"unknown network", host("bogus:nc %h %p", ""), `"bogus" is not a registered network`},
		{"layer as network", host("dgram:nc %h %p", ""), `"dgram" is not a registered network`},
		{"network declared by expression", host("test-nc://%h:%p", ""), `"test-nc" is itself declared by expression`},
		{"%a for a host address", host("cmd:nc %a", ""), `placeholder "%a"`},
		{"%p for a path address", NetworkSpec{AddressKind: AddressPath, Dial: "cmd:nc -U %h %p"}, `placeholder "%p"`},
		{"%h for an opaque address", NetworkSpec{AddressKind: AddressOpaque, Dial: "cmd:%h"}, `placeholder "%h"`},
		{"unknown placeholder", host("cmd:nc %h %x", ""), `placeholder "%x"`},
		{"lone percent", host("cmd:nc %h %p %", ""), `placeholder "%"`},
		{"layer requiring a plane the network lacks", host("test-quic+cmd:nc %h %p", ""), `"test-quic" requires`},
		{"packet required over lossy datagrams", host("test-dtls+dgram+cmd:nc %h %p", ""), "datagram boundaries"},
		{"plane with dial", NetworkSpec{Plane: Stream, AddressKind: AddressHost, Dial: "cmd:nc %h %p"}, "Plane set with Dial"},
		{"listen without dial", NetworkSpec{Plane: Stream, AddressKind: AddressHost, Listen: "cmd:nc -l %h %p"}, "Listen without Dial"},
		{"listen with other layers", host("dgram+cmd:nc -u %h %p", "cmd:nc -u -l %h %p"), "Listen differs from Dial"},
		{"listen over another network", host("cmd:nc %h %p", "test-cmd:nc -l %h %p"), "Listen differs from Dial"},
		{"unparsable listen", host("cmd:nc %h %p", "nc -l %h %p"), "Listen: unparsable"},
		{"listen with unknown placeholder", host("cmd:nc %h %p", "cmd:nc -l %h %x"), `Listen: placeholder "%x"`},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := fmt.Sprintf("test-rejected-%d", i)
			if msg := panicked(func() { RegisterNetwork(name, tt.spec) }); !strings.Contains(msg, tt.want) {
				t.Fatalf("RegisterNetwork panicked with %q, want it to name %s", msg, tt.want)
			}
			if _, ok := lookupNetwork(name); ok {
				t.Fatalf("rejected network %q was registered", name)
			}
		})
	}
}

func TestExpressionNetworkRoundTrips(t *testing.T) {
	tests := []struct {
		uri  string
		want Chain
	}{
		{"test-nc://127.0.0.1:1", Chain{Endpoint: Endpoint{Network: "test-nc", Address: "127.0.0.1:1"}}},
		{
			"test-http+test-nc://u:p@127.0.0.1:1",
			Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u", "password": "p"}}}, Endpoint: Endpoint{Network: "test-nc", Address: "127.0.0.1:1"}},
		},
		{"test-nc-udp://[fe80::1%25en0]:53", Chain{Endpoint: Endpoint{Network: "test-nc-udp", Address: "[fe80::1%en0]:53"}}},
		{"test-nc-unix:///tmp/a%20b.sock", Chain{Endpoint: Endpoint{Network: "test-nc-unix", Address: "/tmp/a b.sock"}}},
		{"test-cmd-packet:nc -u host 53", Chain{Endpoint: Endpoint{Network: "test-cmd-packet", Address: "nc -u host 53"}}},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got, err := ParseURI(tt.uri)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("ParseURI mismatch (-want +got):\n%s", diff)
			}
			if back, err := got.URI(); err != nil || back != tt.uri {
				t.Fatalf("URI() = %q, %v; want %q", back, err, tt.uri)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var again Chain
			if err := json.Unmarshal(data, &again); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(got, again); diff != "" {
				t.Fatalf("json roundtrip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
