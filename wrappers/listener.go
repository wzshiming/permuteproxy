package wrappers

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func NewListenerWrapper(listener protocols.Listener, connWrapperFunc protocols.ConnWrapperFunc) protocols.Listener {
	return &listenerWrapper{
		ConnWrapperFunc: connWrapperFunc,
		Listener:        listener,
	}
}

type listenerWrapper struct {
	protocols.ConnWrapperFunc
	protocols.Listener
}

func (l *listenerWrapper) Accept() (protocols.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn, err = l.ConnWrapperFunc(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
