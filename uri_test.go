package permuteproxy

import (
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
		{uri: "test-http://" + addr, want: Chain{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "test-http+tcp://" + addr, want: Chain{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Network: "tcp", Address: addr}}},
		{
			uri: "test-https://u:p@" + addr + "?tls_skip_verify=true",
			want: Chain{
				Layers: []Layer{
					{Scheme: "test-http", Options: Options{"username": "u", "password": "p"}},
					{Scheme: "test-tls", Options: Options{"tls_skip_verify": "true"}},
				},
				Endpoint: Endpoint{Address: addr},
			},
		},
		{uri: "test-http://u:@" + addr, want: Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u", "password": ""}}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "test-http://u@" + addr, want: Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u"}}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "test-ss://" + addr, want: Chain{Layers: []Layer{{Scheme: "test-ss"}}, Endpoint: Endpoint{Address: addr}}},
		{uri: "test-ss+tcp://aes:p@" + addr, want: Chain{Layers: []Layer{{Scheme: "test-ss", Options: Options{"username": "aes", "password": "p"}}}, Endpoint: Endpoint{Network: "tcp", Address: addr}}},
		{uri: "test-ss+udp://" + addr, want: Chain{Layers: []Layer{{Scheme: "test-ss"}}, Endpoint: Endpoint{Network: "udp", Address: addr}}},
		{uri: "test-socks5+test-snappy+unix://./test.sock", want: Chain{Layers: []Layer{{Scheme: "test-socks5"}, {Scheme: "test-snappy"}}, Endpoint: Endpoint{Network: "unix", Address: "./test.sock"}}},
		{uri: "test-http+unix://u:p@/tmp/test.sock", want: Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u", "password": "p"}}}, Endpoint: Endpoint{Network: "unix", Address: "/tmp/test.sock"}}},
		{uri: "test-https+unix://./test.sock", want: Chain{Layers: []Layer{{Scheme: "test-http"}, {Scheme: "test-tls"}}, Endpoint: Endpoint{Network: "unix", Address: "./test.sock"}}},
		{uri: "test-ss+unix://aes:p@./test.sock", want: Chain{Layers: []Layer{{Scheme: "test-ss", Options: Options{"username": "aes", "password": "p"}}}, Endpoint: Endpoint{Network: "unix", Address: "./test.sock"}}},
		{uri: "test-cmd:ssh -W %h:%p host", want: Chain{Endpoint: Endpoint{Network: "test-cmd", Address: "ssh -W %h:%p host"}}},
		{uri: "test-socks5+test-cmd:nc host 1", want: Chain{Layers: []Layer{{Scheme: "test-socks5"}}, Endpoint: Endpoint{Network: "test-cmd", Address: "nc host 1"}}},
		{
			uri:  "test-http+test-cmd:nc host 1?username=u&password=p",
			want: Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u", "password": "p"}}}, Endpoint: Endpoint{Network: "test-cmd", Address: "nc host 1"}},
			back: "test-http+test-cmd:nc host 1?password=p&username=u",
		},
		{uri: "test-http+unix://./a%3Fb%23c.sock", want: Chain{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Network: "unix", Address: "./a?b#c.sock"}}},
		{uri: "test-http+unix://./u@x.sock", want: Chain{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Network: "unix", Address: "./u@x.sock"}}},
		{
			uri:  "test-ssh://u@" + addr + "?identity_file=a&identity_file=b",
			want: Chain{Layers: []Layer{{Scheme: "test-ssh", Options: Options{"username": "u", "identity_file": "b"}}}, Endpoint: Endpoint{Address: addr}},
			back: "test-ssh://u@" + addr + "?identity_file=b",
		},
		{
			uri:  "test-tls+test-tls://" + addr + "?tls_skip_verify=true",
			want: Chain{Layers: []Layer{{Scheme: "test-tls", Options: Options{"tls_skip_verify": "true"}}, {Scheme: "test-tls"}}, Endpoint: Endpoint{Address: addr}},
		},
		{
			uri:  "test-http://" + addr + "?username=u",
			want: Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u"}}}, Endpoint: Endpoint{Address: addr}},
			back: "test-http://u@" + addr,
		},
		{uri: "test-http+test-quic://" + addr, want: Chain{Layers: []Layer{{Scheme: "test-http"}, {Scheme: "test-quic"}}, Endpoint: Endpoint{Address: addr}}},
		{
			uri:  "test-https://" + addr + "?tls_cert_file=&tls_key_file=",
			want: Chain{Layers: []Layer{{Scheme: "test-http"}, {Scheme: "test-tls", Options: Options{"tls_cert_file": "", "tls_key_file": ""}}}, Endpoint: Endpoint{Address: addr}},
		},
		{
			uri:  "test-ssh://u@" + addr + "?authorized_data=&identity_data=",
			want: Chain{Layers: []Layer{{Scheme: "test-ssh", Options: Options{"username": "u", "authorized_data": "", "identity_data": ""}}}, Endpoint: Endpoint{Address: addr}},
		},
		{uri: "test-http+unix:///tmp/test.sock", want: Chain{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Network: "unix", Address: "/tmp/test.sock"}}},
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
		"invalid:",
		"xxx://x",
		"tcp+xxx://x",
		"xxx+tcp://x",
		"xxx+xxx+tcp://x",
		"tcp+udp://x",
		"tcp://",
		"tcp://u:p@x",
		"test-http+test-tls+udp://x",
		"test-quic+tcp://x",
		"test-tls+test-socks5://x",
		"test-http://x?bogus=1",
		"test-socks4://u:p@x",
		"test-http://u:p%qZ@x",
		"test-http://u:p@x?password=%qZ",
		"test-http://x?%qZ=1",
		"test-http://u:p@x:qZ",
	} {
		t.Run(uri, func(t *testing.T) {
			_, err := ParseURI(uri)
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("ParseURI(%q) = %v, want ErrInvalidChain", uri, err)
			}
			if msg := err.Error(); strings.Contains(msg, "u:p") || strings.Contains(msg, "qZ") {
				t.Fatalf("error echoes input: %v", err)
			}
		})
	}
}

func TestURIRejectsUnrepresentable(t *testing.T) {
	tests := []Chain{
		{Layers: []Layer{{Scheme: "test-tls"}, {Scheme: "test-tls", Options: Options{"tls_skip_verify": "true"}}}, Endpoint: Endpoint{Address: "x:1"}},
		{Layers: []Layer{{Scheme: "test-tls", Options: Options{"tls_skip_verify": "true"}}, {Scheme: "test-tls", Options: Options{"tls_skip_verify": "true"}}}, Endpoint: Endpoint{Address: "x:1"}},
		{Layers: []Layer{{Scheme: "test-http", Options: Options{"bogus": "1"}}}, Endpoint: Endpoint{Address: "x:1"}},
		{Layers: []Layer{{Scheme: "xxx"}}, Endpoint: Endpoint{Address: "x:1"}},
		{Endpoint: Endpoint{Network: "test-cmd", Address: "nc host 1?x"}},
		{Endpoint: Endpoint{Network: "test-cmd", Address: "nc host#1"}},
		{Endpoint: Endpoint{Network: "test-cmd", Address: "/usr/bin/nc host 1"}},
		{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Network: "unix", Address: "u@x.sock"}},
		{Endpoint: Endpoint{Network: "unix", Address: "a:b.sock"}},
		{Endpoint: Endpoint{Network: "tcp", Address: "a/b"}},
		{Layers: []Layer{{Scheme: "test-http"}}, Endpoint: Endpoint{Address: "a b"}},
	}
	for _, c := range tests {
		if _, err := c.URI(); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("URI() of %+v = %v, want ErrInvalidChain", c, err)
		}
	}
}
