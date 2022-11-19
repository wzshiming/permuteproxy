package permuteproxy

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

type Define struct {
	Handler
	protocols.SchemeInfo
}

func Registry(scheme string, f Define) {
	protocols.RegisterScheme(scheme, f.SchemeInfo)
	RegisterHandle(scheme, f.Handler)
}

type Handler struct {
	Dialer              Dialer
	DialerWrapper       DialerWrapper
	ListenConfig        ListenConfig
	ListenConfigWrapper ListenConfigWrapper
	NewRunner           NewRunner
}

var handle = map[string]Handler{}

func RegisterHandle(scheme string, h Handler) {
	handle[scheme] = h
}
