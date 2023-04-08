package command

import (
	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	metas := map[string]permuteproxy.Define{
		"cmd": {
			Handler: permuteproxy.Handler{
				Dialer:        Command,
				ListenConfig:  Command,
				CommandDialer: Command.CommandDialer,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressOpaque,
			},
		},
		"cmd-nc": {
			Handler: permuteproxy.Handler{
				Dialer:       NetCatTCP,
				ListenConfig: NetCatTCP,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressHost,
			},
		},
		"cmd-nc-unix": {
			Handler: permuteproxy.Handler{
				Dialer:       NetCatUnix,
				ListenConfig: NetCatUnix,
			},
			SchemeInfo: protocols.SchemeInfo{
				Kind:        protocols.KindStream,
				Base:        protocols.KindNone,
				AddressKind: protocols.AddressPath,
			},
		},
	}
	for scheme, meta := range metas {
		permuteproxy.Registry(scheme, meta)
	}
}
