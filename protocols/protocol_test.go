package protocols_test

import (
	"net/url"
	"testing"

	"github.com/wzshiming/permuteproxy/protocols"
	_ "github.com/wzshiming/permuteproxy/protocols/anyproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/httpproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local"
	_ "github.com/wzshiming/permuteproxy/protocols/shadowsocks"
	_ "github.com/wzshiming/permuteproxy/protocols/snappy"
	_ "github.com/wzshiming/permuteproxy/protocols/socks4"
	_ "github.com/wzshiming/permuteproxy/protocols/socks5"
	_ "github.com/wzshiming/permuteproxy/protocols/sshproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/tls"

	"github.com/google/go-cmp/cmp"
)

func TestProtocol_URI(t *testing.T) {
	tests := []struct {
		name     string
		protocol *protocols.Protocol
		want     *url.URL
	}{
		{
			name: "tcp",
			protocol: &protocols.Protocol{
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
			want: &url.URL{
				Host:   "127.0.0.1:8080",
				Scheme: "tcp",
			},
		},
		{
			name: "http",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
			want: &url.URL{
				Host:   "127.0.0.1:8080",
				Scheme: "http",
			},
		},
		{
			name: "http with username and password",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
						Metadata: protocols.Metadata{
							"username": []string{"username"},
							"password": []string{"password"},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
			want: &url.URL{
				Scheme: "http",
				Host:   "127.0.0.1:8080",
				User:   url.UserPassword("username", "password"),
			},
		},
		{
			name: "https",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
					{
						Scheme: "tls",
						Metadata: protocols.Metadata{
							"tls_key_file":  []string{""},
							"tls_cert_file": []string{""},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
			want: &url.URL{
				Scheme: "https",
				Host:   "127.0.0.1:8080",
				RawQuery: url.Values{
					"tls_key_file":  []string{""},
					"tls_cert_file": []string{""},
				}.Encode(),
			},
		},
		{
			name: "http with unix",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "unix",
					Address: "/tmp/test.sock",
				},
			},
			want: &url.URL{
				Path:   "/tmp/test.sock",
				Scheme: "http+unix",
			},
		},
		{
			name: "http with local unix",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "unix",
					Address: "./test.sock",
				},
			},
			want: &url.URL{
				Path:   "./test.sock",
				Scheme: "http+unix",
			},
		},
		{
			name: "http with quic",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
					{
						Scheme: "quic",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "udp",
					Address: "127.0.0.1:8080",
				},
			},
			want: &url.URL{
				Host:   "127.0.0.1:8080",
				Scheme: "http+quic",
			},
		},
		{
			name: "ssh with username",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "ssh",
						Metadata: protocols.Metadata{
							"username": []string{"username"},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:22",
				},
			},
			want: &url.URL{
				Host:   "127.0.0.1:22",
				Scheme: "ssh",
				User:   url.User("username"),
			},
		},
		{
			name: "ssh with username and key",
			protocol: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "ssh",
						Metadata: protocols.Metadata{
							"username":        []string{"username"},
							"authorized_data": []string{""},
							"identity_data":   []string{""},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:22",
				},
			},
			want: &url.URL{
				Host:   "127.0.0.1:22",
				Scheme: "ssh",
				User:   url.User("username"),
				RawQuery: url.Values{
					"authorized_data": {""},
					"identity_data":   {""},
				}.Encode(),
			},
		},
	}
	compareUser := cmp.Comparer(func(x, y *url.Userinfo) bool {
		return x.String() == y.String()
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.protocol.URI()
			if diff := cmp.Diff(tt.want, got, compareUser); diff != "" {
				t.Errorf("Protocol.URI() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewProtocolFrom(t *testing.T) {
	tests := []struct {
		name    string
		uri     *url.URL
		want    *protocols.Protocol
		wantErr bool
	}{
		{
			name: "tcp",
			uri: &url.URL{
				Scheme: "tcp",
				Host:   "127.0.0.1:8080",
			},
			want: &protocols.Protocol{
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
		},
		{
			name: "http",
			uri: &url.URL{
				Host:   "127.0.0.1:8080",
				Scheme: "http",
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
		},
		{
			name: "http with username and password",
			uri: &url.URL{
				Scheme: "http",
				Host:   "127.0.0.1:8080",
				User:   url.UserPassword("username", "password"),
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
						Metadata: protocols.Metadata{
							"username": []string{"username"},
							"password": []string{"password"},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
		},
		{
			name: "https",
			uri: &url.URL{
				Scheme: "https",
				Host:   "127.0.0.1:8080",
				RawQuery: url.Values{
					"tls_cert_file": []string{""},
					"tls_key_file":  []string{""},
				}.Encode(),
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
					{
						Scheme: "tls",
						Metadata: protocols.Metadata{
							"tls_cert_file": []string{""},
							"tls_key_file":  []string{""},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:8080",
				},
			},
		},
		{
			name: "http with unix",
			uri: &url.URL{
				Path:   "/tmp/test.sock",
				Scheme: "http+unix",
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "unix",
					Address: "/tmp/test.sock",
				},
			},
		},
		{
			name: "http with local unix",
			uri: &url.URL{
				Path:   "./test.sock",
				Scheme: "http+unix",
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "http",
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "unix",
					Address: "./test.sock",
				},
			},
		},
		{
			name: "ssh with username",
			uri: &url.URL{
				Host:   "127.0.0.1:22",
				Scheme: "ssh",
				User:   url.User("username"),
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "ssh",
						Metadata: protocols.Metadata{
							"username": []string{"username"},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:22",
				},
			},
		},
		{
			name: "ssh with username and key",
			uri: &url.URL{
				Host:   "127.0.0.1:22",
				Scheme: "ssh",
				User:   url.User("username"),
				RawQuery: url.Values{
					"authorized_data": {""},
					"identity_data":   {""},
				}.Encode(),
			},
			want: &protocols.Protocol{
				Wrappers: []protocols.Wrapper{
					{
						Scheme: "ssh",
						Metadata: protocols.Metadata{
							"username":        []string{"username"},
							"identity_data":   []string{""},
							"authorized_data": []string{""},
						},
					},
				},
				Endpoint: protocols.Endpoint{
					Network: "tcp",
					Address: "127.0.0.1:22",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protocols.NewProtocolFrom(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProtocolFrom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("NewProtocolFrom() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConsistency(t *testing.T) {

	tests := []struct {
		name    string
		rawURI  string
		wantErr bool
	}{
		{
			name:    "empty",
			rawURI:  "",
			wantErr: true,
		},
		{
			name:   "tcp",
			rawURI: "tcp://127.0.0.1:1000",
		},
		{
			name:   "http",
			rawURI: "http://127.0.0.1:1000",
		},
		{
			name:   "http with unix",
			rawURI: "http+unix:///tmp/foo.sock",
		},
		{
			name:   "http with local unix",
			rawURI: "http+unix://./foo.sock",
		},
		{
			name:   "ssh",
			rawURI: "ssh://username@127.0.0.1:22",
		},
		{
			name:    "unknown 1",
			rawURI:  "xxx://xxx",
			wantErr: true,
		},
		{
			name:    "unknown 2",
			rawURI:  "xxx+tcp://xxx",
			wantErr: true,
		},
		{
			name:    "unknown 3",
			rawURI:  "tcp+xxx://xxx",
			wantErr: true,
		},
		{
			name:    "unknown 4",
			rawURI:  "tcp+udp://xxx",
			wantErr: true,
		},
		{
			name:    "unknown 5",
			rawURI:  "xxx+xxx+tcp://xxx",
			wantErr: true,
		},
		{
			name:    "error 1",
			rawURI:  ":",
			wantErr: true,
		},
		{
			name:    "error 2",
			rawURI:  "invalid:",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protocols.NewProtocol(tt.rawURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProtocol() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if diff := cmp.Diff(got.String(), tt.rawURI); diff != "" {
					t.Errorf("NewProtocol() and String() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
