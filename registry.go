package permuteproxy

import (
	"fmt"

	"github.com/wzshiming/permuteproxy/protocols"
)

var ErrNoProxy = fmt.Errorf("no proxy")

type Define struct {
	Handler
	protocols.SchemeInfo
}

func Registry(scheme string, f Define) {
	protocols.RegisterScheme(scheme, f.SchemeInfo)
	RegisterHandle(scheme, f.Handler)
}

type Handler struct {
	Dialer                    Dialer
	DialerWrapper             DialerWrapper
	ListenConfig              ListenConfig
	ListenConfigWrapper       ListenConfigWrapper
	ListenPacketConfig        ListenPacketConfig
	ListenPacketConfigWrapper ListenPacketConfigWrapper
	CommandDialer             CommandDialer
	CommandDialerWrapper      CommandDialerWrapper
	NewRunner                 NewRunner
}

var handle = map[string]Handler{}

func RegisterHandle(scheme string, h Handler) {
	handle[scheme] = h
}
