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

A proxy is written as a URI whose scheme joins layers with `+`, outermost first, down to the network that carries them:

```
socks5+snappy+tls://user:pass@127.0.0.1:1080
│      │      │
│      │      └─ encrypted by TLS, over tcp
│      └──────── compressed by snappy
└─────────────── spoken as SOCKS5
```

Any proxy protocol can be stacked on any adapters and network that fit it, so one URI names a combination no single protocol offers:

| URI | Proxy |
| --- | --- |
| `socks5://127.0.0.1:1080` | SOCKS5 over tcp |
| `https://127.0.0.1:8443` | HTTP proxy over TLS, an alias of `http+tls` |
| `socks5+snappy+tls://127.0.0.1:1080` | SOCKS5, compressed, over TLS |
| `http+snappy+quic://127.0.0.1:8443` | HTTP proxy, compressed, over QUIC streams on udp |
| `ssh+unix:///run/proxy.sock` | SSH over a unix socket |
| `cmd:ssh -W %h:%p jump` | a command run per dial as the client |
| `nc:ssh jump` | netcat run per dial as the client, here on `jump` through ssh |

A command client fills `%h` with the host, or the socket path of a unix address, `%p` with the port and `%n` with the network, anywhere in the line, quotes included, as in `cmd:sh -c 'nc %h %p'`. Its `Listen` runs the command once per connection, so `cmd:nc -l %h %p` accepts at an address. A host or path with a character a shell would not read as plain text is refused.

`nc:` is the command client of netcat over tcp, udp and unix sockets, run behind what follows the scheme, so `nc:ssh jump` runs it on `jump`.

The same URI serves the proxy on one side and dials through it on the other:

```go
package main

import (
	"context"
	"log"

	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/all"
)

func main() {
	ctx := context.Background()

	// Server: SOCKS5, compressed by snappy, over TLS with a self-signed certificate.
	go func() {
		log.Fatal(permuteproxy.ListenAndServe(ctx, "socks5+snappy+tls://user:pass@127.0.0.1:1080?tls_self_signed=true"))
	}()

	// Client: the same layers, trusting the self-signed certificate.
	client, err := permuteproxy.NewClient("socks5+snappy+tls://user:pass@127.0.0.1:1080?tls_skip_verify=true")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := client.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
```

`NewServer` returns the server instead of running it, and `ClientEngine`, `ServerEngine` and `TransportEngine` build a chain over networks of your own.

## License

Licensed under the MIT License. See [LICENSE](https://github.com/wzshiming/permuteproxy/blob/master/LICENSE) for the full license text.
