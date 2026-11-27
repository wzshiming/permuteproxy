# Permute Proxy

Permute Proxy is a permuting proxy engine that combines multiple protocols into a single proxy protocol.

[![GoDoc](https://godoc.org/github.com/wzshiming/permuteproxy?status.svg)](https://godoc.org/github.com/wzshiming/permuteproxy)
[![GitHub license](https://img.shields.io/github/license/wzshiming/permuteproxy.svg)](https://github.com/wzshiming/permuteproxy/blob/master/LICENSE)

This project is to add protocol support for the [Bridge](https://github.com/wzshiming/bridge), or it can be used alone

The following is the implementation of other proxy protocols

- [HTTP Proxy](https://github.com/wzshiming/httpproxy)
- [Socks4](https://github.com/wzshiming/socks4)
- [Socks5](https://github.com/wzshiming/socks5)
- [Shadow Socks](https://github.com/wzshiming/shadowsocks)
- [SSH Proxy](https://github.com/wzshiming/sshproxy)
- [Any Proxy](https://github.com/wzshiming/anyproxy)

## Usage

A chain is written as a URI whose scheme joins its layers, outermost first, with `+`, optionally ending in the network the innermost layer runs on:

```
socks5+tls://user:pass@127.0.0.1:1080?tls_server_name=proxy.example
└─┬──┘ └┬┘   └───┬───┘ └─────┬──────┘ └────────────┬──────────────┘
proxy adapter credentials  endpoint            layer options
```

Importing `protocols/all` registers every bundled layer and network; import single packages under `protocols/` to register only those.

Serve a proxy:

```go
package main

import (
	"context"
	"log"

	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/all"
)

func main() {
	// A SOCKS5 server behind TLS, serving a certificate it signs itself.
	chain, err := permuteproxy.ParseURI("socks5+tls://127.0.0.1:1080?tls_self_signed=true")
	if err != nil {
		log.Fatal(err)
	}
	server, err := permuteproxy.Engine{}.Server(chain)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	log.Fatal(server.Run(context.Background()))
}
```

Dial through it. The client is a `Network`, which dials as the `net` package does:

```go
chain, err := permuteproxy.ParseURI("socks5+tls://127.0.0.1:1080?tls_skip_verify=true")
if err != nil {
	log.Fatal(err)
}
client, err := permuteproxy.Engine{}.Client(chain)
if err != nil {
	log.Fatal(err)
}
conn, err := client.DialContext(ctx, "tcp", "example.com:80")
```

`Engine.Transport` builds a chain of adapters alone, such as `tls://127.0.0.1:443`, into a `Transport` that dials and listens at the endpoint. `Engine.Base` and `Engine.Upstream` replace the network a chain reaches its endpoint and a server reaches its targets through, which is how one chain is routed through the client of another.

### Proxy layers

A proxy is the outermost layer of a chain.

| Scheme | Client | Server | Options |
|---|---|---|---|
| `http` (`https` is `http+tls`) | tcp | yes | `username`, `password` |
| `socks4`, `socks4a` | tcp | yes | `username`, `password` |
| `socks5`, `socks5h` | tcp, udp | yes | `username`, `password` |
| `ss`, `shadowsocks` | tcp, udp | yes | `encrypto`, `password` |
| `ssh` | tcp, unix, cmd, udp through a command | yes | `username`, `password`, `identity_file`, `identity_data`, `authorized_file`, `authorized_data`, `hostkey_file`, `hostkey_data`, `udp_command`, `allow_exec` |
| `any` | no | yes, http, socks4, socks5 and ssh on one port | `username`, `password` |

The username and password may be written in the URI's userinfo.

### Adapter layers

An adapter turns the carrier below it into the one the layer above needs.

| Scheme | Carries | Over | Options |
|---|---|---|---|
| `tls` | stream | stream | `tls_server_name`, `tls_skip_verify`, `tls_ca_file`, `tls_cert_file`, `tls_key_file`, `tls_self_signed`, `tls_acme_host`, `tls_acme_cache_dir` |
| `quic` | stream | packet | those of `tls` but the `tls_acme_*` ones |
| `snappy` | stream | stream | none |
| `dgram` | packet, without datagram boundaries | stream | none |

### Networks

| Network | Address | Example |
|---|---|---|
| `tcp`, `udp` | host:port | `tls+tcp://127.0.0.1:443` |
| `unix`, `unixgram` | path | `socks5+unix://./proxy.sock` |
| `cmd` | a command line whose stdio carries the connection | `socks5+cmd:ssh host nc 127.0.0.1 1080` |
| `cmd-nc`, `cmd-nc-udp` | host:port, reached by running `nc` | `socks5+cmd-nc://127.0.0.1:1080` |
| `cmd-nc-unix` | path, reached by running `nc` | `socks5+cmd-nc-unix://./proxy.sock` |
| `cmd-packet` | a command line carrying datagrams | `cmd-packet:ssh host nc -u 1.1.1.1 53` |

A chain without a network runs on `tcp`, `udp` or both, as its innermost layer needs.

## License

Licensed under the MIT License. See [LICENSE](https://github.com/wzshiming/permuteproxy/blob/master/LICENSE) for the full license text.
