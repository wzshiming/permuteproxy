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

Serve a proxy and dial through it, each from a URI:

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

	// Server: serves until ctx ends.
	go func() {
		log.Fatal(permuteproxy.ListenAndServe(ctx, "socks5://user:pass@127.0.0.1:1080"))
	}()

	// Client: dials its targets through the proxy.
	client, err := permuteproxy.NewClient("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

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
