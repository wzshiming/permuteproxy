package permuteproxy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestChainValidate(t *testing.T) {
	tests := []struct {
		name  string
		chain Chain
		ok    bool
	}{
		{"ss auto dual", mk("", "test-ss"), true},
		{"ss over tls", mk("", "test-ss", "test-tls"), true},
		{"ss over udp", mk("udp", "test-ss"), true},
		{"quic over udp", mk("udp", "test-quic"), true},
		{"quic auto", mk("", "test-quic"), true},
		{"socks5 over quic", mk("", "test-socks5", "test-quic"), true},
		{"raw tcp", mk("tcp"), true},
		{"unix", Chain{Endpoint: Endpoint{Network: "unix", Address: "./x.sock"}}, true},
		{"quic over tcp", mk("tcp", "test-quic"), false},
		{"tls over udp", mk("udp", "test-tls"), false},
		{"proxy not outermost", mk("", "test-tls", "test-socks5"), false},
		{"unknown scheme", mk("", "xxx"), false},
		{"unknown network", mk("xxx", "test-tls"), false},
		{"unknown option", Chain{Layers: []Layer{{Scheme: "test-tls", Options: Options{"bogus": "1"}}}, Endpoint: Endpoint{Address: "127.0.0.1:1"}}, false},
		{"auto without layers", mk(""), false},
		{"empty address", Chain{Layers: []Layer{{Scheme: "test-tls"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.chain.Validate()
			if tt.ok != (err == nil) {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Validate() = %v, want ErrInvalidChain", err)
			}
		})
	}
}

func TestChainValidateNamesTheInnermostFailure(t *testing.T) {
	// test-tls fails over udp, which leaves test-ss nothing to preserve.
	if err := mk("udp", "test-ss", "test-tls").Validate(); !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), `"test-tls"`) {
		t.Fatalf("Validate() = %v, want it to name test-tls", err)
	}
}

func TestChainValidateLossy(t *testing.T) {
	tests := []struct {
		name  string
		chain Chain
		names []string // what the error names; nil for a valid chain
	}{
		{"lossy datagrams outermost", mk("tcp", "test-lossy"), nil},
		{"lossy datagrams over cmd", Chain{Layers: []Layer{{Scheme: "test-lossy"}}, Endpoint: Endpoint{Network: "cmd", Address: "nc host 1"}}, nil},
		{"packet required over datagrams with boundaries", mk("tcp", "test-dtls", "test-uot"), nil},
		{"packet preserved over lossy datagrams beside stream", mk("", "test-keep", "test-lossy-keep"), nil},
		{"packet provided above lossy datagrams", mk("", "test-dtls", "test-uot", "test-lossy-keep"), nil},
		{"packet required over lossy datagrams", mk("tcp", "test-dtls", "test-lossy"), []string{`"test-dtls"`, "datagram boundaries"}},
		{"packet required over lossy preserved datagrams", mk("", "test-quic", "test-lossy-keep"), []string{`"test-quic"`, "datagram boundaries"}},
		{"only lossy datagrams preserved", mk("tcp", "test-ss", "test-lossy"), []string{`"test-ss"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.chain.Validate()
			if tt.names == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want a valid chain", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Validate() = %v, want ErrInvalidChain", err)
			}
			for _, name := range tt.names {
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("Validate() = %v, want it to name %s", err, name)
				}
			}
		})
	}
}

func TestLossyPlaneNotOfferedAbove(t *testing.T) {
	calls = nil
	e := TransportEngine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		chain  Chain
		planes Plane
		calls  []string
	}{
		{mk("tcp", "test-lossy"), Packet, []string{"test-lossy.new"}},
		{mk("", "test-lossy-keep"), Stream | Packet, []string{"test-lossy-keep.new"}},
		{mk("", "test-keep", "test-lossy-keep"), Stream, []string{"test-lossy-keep.new", "test-keep.new"}},
	}
	for _, tt := range tests {
		tr, err := e.Transport(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Planes() != tt.planes {
			t.Fatalf("Planes() of %+v = %v, want %v", tt.chain.Layers, tr.Planes(), tt.planes)
		}
		assertCalls(t, tt.calls...)
	}
}

func TestChainJSON(t *testing.T) {
	c := Chain{
		Layers: []Layer{
			{Scheme: "http", Options: Options{"username": "u", "password": ""}},
			{Scheme: "tls", Options: Options{"tls_skip_verify": "true"}},
		},
		Endpoint: Endpoint{Network: "tcp", Address: "127.0.0.1:1"},
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"layers":[{"scheme":"http","options":{"password":"","username":"u"}},{"scheme":"tls","options":{"tls_skip_verify":"true"}}],"endpoint":{"network":"tcp","address":"127.0.0.1:1"}}`
	if string(data) != want {
		t.Fatalf("json = %s\nwant %s", data, want)
	}
	var got Chain
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(c, got); diff != "" {
		t.Fatalf("json roundtrip mismatch (-want +got):\n%s", diff)
	}
	if data, _ = json.Marshal(Chain{Layers: []Layer{{Scheme: "ss"}}, Endpoint: Endpoint{Address: "x:1"}}); string(data) != `{"layers":[{"scheme":"ss"}],"endpoint":{"address":"x:1"}}` {
		t.Fatalf("auto network json = %s", data)
	}
}
