package local

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	metas := map[string]permuteproxy.Define{
		"tcp": {
			Handler: permuteproxy.Handler{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressHost,
			},
		},
		"udp": {
			Handler: permuteproxy.Handler{
				ListenPacketConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindPacket,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressHost,
			},
		},
		"unix": {
			Handler: permuteproxy.Handler{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressPath,
			},
		},
		"unixgram": {
			Handler: permuteproxy.Handler{
				ListenPacketConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindPacket,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressPath,
			},
		},
		"cmd": {
			Handler: permuteproxy.Handler{
				Dialer:        LOCAL,
				ListenConfig:  LOCAL,
				CommandDialer: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressOpaque,
			},
		},
		"cmd-nc": {
			Handler: permuteproxy.Handler{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressHost,
			},
		},
		"cmd-nc-unix": {
			Handler: permuteproxy.Handler{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressPath,
			},
		},
	}
	for scheme, meta := range metas {
		permuteproxy.Register(scheme, meta)
	}
}
