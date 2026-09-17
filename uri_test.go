package permuteproxy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseURI(t *testing.T) {
	addr := "127.0.0.1:1"
	tests := []struct {
		uri  string
		want Chain
		back string
	}{
		{uri: "tcp://" + addr, want: Chain{Endpoint: Endpoint{Network: "tcp", Address: addr}}},
		{uri: "http://" + addr, want: Chain{Layers: []Layer{{Scheme: "http"}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "http+tcp://" + addr, want: Chain{Layers: []Layer{{Scheme: "http"}}, Endpoint: Endpoint{Network: "tcp", Address: addr}}},
		{
			uri: "https://u:p@" + addr + "?tls_skip_verify=true",
			want: Chain{
				Layers: []Layer{
					{Scheme: "http", Options: Options{"username": "u", "password": "p"}},
					{Scheme: "tls", Options: Options{"tls_skip_verify": "true"}},
				},
				Endpoint: Endpoint{Address: addr},
			},
		},
		{uri: "http://u:@" + addr, want: Chain{Layers: []Layer{{Scheme: "http", Options: Options{"username": "u", "password": ""}}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "http://u@" + addr, want: Chain{Layers: []Layer{{Scheme: "http", Options: Options{"username": "u"}}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "ss://" + addr, want: Chain{Layers: []Layer{{Scheme: "ss"}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "ss+tcp://aes:p@" + addr, want: Chain{Layers: []Layer{{Scheme: "ss", Options: Options{"username": "aes", "password": "p"}}}, Endpoint: Endpoint{Network: "tcp", Address: addr}}},
		{uri: "ss+udp://" + addr, want: Chain{Layers: []Layer{{Scheme: "ss"}}, Endpoint: Endpoint{Network: "udp", Address: addr}}},
		{uri: "socks5+snappy+unix://./test.sock", want: Chain{Layers: []Layer{{Scheme: "socks5"}, {Scheme: "snappy"}}, Endpoint: Endpoint{Network: "unix", Address: "./test.sock"}}},
		{uri: "http+unix://u:p@/tmp/test.sock", want: Chain{Layers: []Layer{{Scheme: "http", Options: Options{"username": "u", "password": "p"}}}, Endpoint: Endpoint{Network: "unix", Address: "/tmp/test.sock"}}},
		{uri: "https+unix://./test.sock", want: Chain{Layers: []Layer{{Scheme: "http"}, {Scheme: "tls"}}, Endpoint: Endpoint{Network: "unix", Address: "./test.sock"}}},
		{uri: "ss+unix://aes:p@./test.sock", want: Chain{Layers: []Layer{{Scheme: "ss", Options: Options{"username": "aes", "password": "p"}}}, Endpoint: Endpoint{Network: "unix", Address: "./test.sock"}}},
		{uri: "cmd:ssh -W %h:%p host", want: Chain{Endpoint: Endpoint{Network: "cmd", Address: "ssh -W %h:%p host"}}},
		{uri: "socks5+cmd:nc host 1", want: Chain{Layers: []Layer{{Scheme: "socks5"}}, Endpoint: Endpoint{Network: "cmd", Address: "nc host 1"}}},
		{
			uri:  "ssh://u@" + addr + "?identity_file=a&identity_file=b",
			want: Chain{Layers: []Layer{{Scheme: "ssh", Options: Options{"username": "u", "identity_file": "b"}}}, Endpoint: Endpoint{Address: addr}},
			back: "ssh://u@" + addr + "?identity_file=b",
		},
		{
			uri:  "tls+tls://" + addr + "?tls_skip_verify=true",
			want: Chain{Layers: []Layer{{Scheme: "tls", Options: Options{"tls_skip_verify": "true"}}, {Scheme: "tls"}}, Endpoint: Endpoint{Address: addr}},
		},
		{
			uri:  "http://" + addr + "?username=u",
			want: Chain{Layers: []Layer{{Scheme: "http", Options: Options{"username": "u"}}}, Endpoint: Endpoint{Address: addr}},
			back: "http://u@" + addr,
		},
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
			back, err := got.URI()
			if err != nil {
				t.Fatal(err)
			}
			want := tt.back
			if want == "" {
				want = tt.uri
			}
			if back != want {
				t.Fatalf("URI() = %q, want %q", back, want)
			}
			again, err := ParseURI(back)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(got, again); diff != "" {
				t.Fatalf("reparse mismatch (-first +again):\n%s", diff)
			}
		})
	}
}

func TestParseURIErrors(t *testing.T) {
	for _, uri := range []string{
		"",
		":",
		"xxx://x",
		"tcp+xxx://x",
		"xxx+tcp://x",
		"tcp://",
		"tcp://u:p@x",
		"http+tls+udp://x",
		"quic+tcp://x",
		"tls+socks5://x",
		"http://x?bogus=1",
		"socks4://u:p@x",
	} {
		t.Run(uri, func(t *testing.T) {
			_, err := ParseURI(uri)
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("ParseURI(%q) = %v, want ErrInvalidChain", uri, err)
			}
			if strings.Contains(err.Error(), "u:p") {
				t.Fatalf("error leaks credentials: %v", err)
			}
		})
	}
}

func TestURIRejectsUnrepresentable(t *testing.T) {
	tests := []Chain{
		{Layers: []Layer{{Scheme: "tls"}, {Scheme: "tls", Options: Options{"tls_skip_verify": "true"}}}, Endpoint: Endpoint{Address: "x:1"}},
		{Layers: []Layer{{Scheme: "tls", Options: Options{"tls_skip_verify": "true"}}, {Scheme: "tls", Options: Options{"tls_skip_verify": "true"}}}, Endpoint: Endpoint{Address: "x:1"}},
		{Layers: []Layer{{Scheme: "http", Options: Options{"bogus": "1"}}}, Endpoint: Endpoint{Address: "x:1"}},
		{Layers: []Layer{{Scheme: "xxx"}}, Endpoint: Endpoint{Address: "x:1"}},
	}
	for _, c := range tests {
		if _, err := c.URI(); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("URI() of %+v = %v, want ErrInvalidChain", c, err)
		}
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
