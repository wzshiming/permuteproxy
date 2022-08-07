package wrappers

import (
	"context"

	"github.com/wzshiming/permuteproxy/protocols"
)

func NewListenConfigWrapper(listenConfig protocols.ListenConfig, connWrapperFunc protocols.ConnWrapperFunc) protocols.ListenConfig {
	return &listenConfigWrapper{
		ListenConfig:    listenConfig,
		ConnWrapperFunc: connWrapperFunc,
	}
}

type listenConfigWrapper struct {
	protocols.ConnWrapperFunc
	protocols.ListenConfig
}

func (l *listenConfigWrapper) Listen(ctx context.Context, network, address string) (protocols.Listener, error) {
	listener, err := l.ListenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewListenerWrapper(listener, l.ConnWrapperFunc), nil
}
