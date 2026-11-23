package all_test

import (
	"testing"

	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/all"
)

func TestAllRegistersQUIC(t *testing.T) {
	c, err := permuteproxy.ParseURI("socks5+quic://127.0.0.1:1")
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		t.Fatal(err)
	}
}
