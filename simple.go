package permuteproxy

import (
	"context"
	"io"
)

// Client is a proxy client: a Network reaching its targets through the proxy, whose Close releases it.
type Client interface {
	Network
	io.Closer
}

// unclosed is a Client of a Network that holds nothing to release.
type unclosed struct{ Network }

func (unclosed) Close() error { return nil }

// NewClient builds the client of the proxy chain uri names, such as socks5://user:pass@127.0.0.1:1080 or cmd:ssh -W %h:%p jump, as a zero ClientEngine does.
func NewClient(uri string) (Client, error) {
	c, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	n, err := ClientEngine{}.Client(c)
	if err != nil {
		return nil, err
	}
	if client, ok := n.(Client); ok {
		return client, nil
	}
	return unclosed{n}, nil
}

// NewServer builds the server of the proxy chain uri names, such as socks5://user:pass@:1080, as a zero ServerEngine does; its Run binds and serves.
func NewServer(uri string) (Server, error) {
	c, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return ServerEngine{}.Server(c)
}

// ListenAndServe serves the proxy chain uri names until serving fails or ctx ends, returning nil for the latter.
func ListenAndServe(ctx context.Context, uri string) error {
	s, err := NewServer(uri)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Run(ctx)
}
