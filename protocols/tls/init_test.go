package tls_test

import (
	"testing"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
	_ "github.com/wzshiming/permuteproxy/protocols/tls"
)

func TestTLSURIsAcceptEveryOptionKey(t *testing.T) {
	for _, key := range tlsutils.OptionKeys() {
		if _, err := permuteproxy.ParseURI("tls://127.0.0.1:1?" + key + "="); err != nil {
			t.Errorf("tls URI with %s: %v", key, err)
		}
	}
}
