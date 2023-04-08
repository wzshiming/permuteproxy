package permuteproxy

import (
	"context"
)

type Proxy struct {
	Dialer             Dialer
	ListenConfig       ListenConfig
	ListenPacketConfig ListenPacketConfig
	CommandDialer      CommandDialer
}

type proxyKey struct{}

func withContext(ctx context.Context, d *Proxy) context.Context {
	return context.WithValue(ctx, proxyKey{}, d)
}

func FromContext(ctx context.Context) (*Proxy, bool) {
	d, ok := ctx.Value(proxyKey{}).(*Proxy)
	return d, ok
}

func (p Proxy) withDialer(d Dialer) *Proxy {
	return &Proxy{
		Dialer:             d,
		ListenConfig:       p.ListenConfig,
		ListenPacketConfig: p.ListenPacketConfig,
		CommandDialer:      p.CommandDialer,
	}
}

func (p Proxy) withListenConfig(l ListenConfig) *Proxy {
	return &Proxy{
		Dialer:             p.Dialer,
		ListenConfig:       l,
		ListenPacketConfig: p.ListenPacketConfig,
		CommandDialer:      p.CommandDialer,
	}
}

func (p Proxy) withListenPacketConfig(l ListenPacketConfig) *Proxy {
	return &Proxy{
		Dialer:             p.Dialer,
		ListenConfig:       p.ListenConfig,
		ListenPacketConfig: l,
		CommandDialer:      p.CommandDialer,
	}
}

func (p Proxy) withCommandDialer(c CommandDialer) *Proxy {
	return &Proxy{
		Dialer:             p.Dialer,
		ListenConfig:       p.ListenConfig,
		ListenPacketConfig: p.ListenPacketConfig,
		CommandDialer:      c,
	}
}
