package permuteproxy

import (
	"io"
	"testing"
)

func TestTransportAndClientCloseOnce(t *testing.T) {
	base := &closableNet{fakeNet{name: "base"}}
	tests := []struct {
		uri   string
		proxy bool
		want  []string
	}{
		{"closable+tcp://127.0.0.1:1", false, []string{"closable.close"}},
		{"test-tls+closable+tcp://127.0.0.1:1", false, []string{"closable.close"}},
		{"closable+closable+tcp://127.0.0.1:1", false, []string{"closable.close", "closable.close"}},
		{"closable+test-tls://127.0.0.1:1", false, []string{"closable.close"}},
		{"test-tls://127.0.0.1:1", false, nil},
		{"closableproxy+tcp://127.0.0.1:1", true, []string{"closableproxy.close"}},
		{"closableproxy+closable+tcp://127.0.0.1:1", true, []string{"closableproxy.close", "closable.close"}},
		{"test-http+closable+tcp://127.0.0.1:1", true, []string{"closable.close"}},
		{"closableproxy://127.0.0.1:1", true, []string{"closableproxy.close"}},
		{"test-http://127.0.0.1:1", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			var got any
			var err error
			if tt.proxy {
				got, err = ClientEngine{Base: base}.Client(parse(t, tt.uri))
			} else {
				got, err = TransportEngine{Base: base}.Transport(parse(t, tt.uri))
			}
			if err != nil {
				t.Fatal(err)
			}
			c, ok := got.(io.Closer)
			if !ok {
				t.Fatal("result has no Close")
			}
			calls = nil
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.want...)
			if err := c.Close(); err != nil {
				t.Fatalf("second Close = %v", err)
			}
			assertCalls(t)
		})
	}
}
