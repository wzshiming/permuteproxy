package local

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	metas := map[string]protocols.Define{
		"tcp": {
			Handle: protocols.Handle{
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
			Handle: protocols.Handle{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindPacket,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressHost,
			},
		},
		"unix": {
			Handle: protocols.Handle{
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
			Handle: protocols.Handle{
				Dialer:       LOCAL,
				ListenConfig: LOCAL,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindPacket,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressPath,
			},
		},
	}
	for scheme, meta := range metas {
		protocols.Registry(scheme, meta)
	}
}
