package permuteproxy

import (
	"context"
	"errors"
	"strings"
)

type Plane uint8

const (
	Stream Plane = 1 << iota
	Packet
)

func (p Plane) String() string {
	var names []string
	if p&Stream != 0 {
		names = append(names, "stream")
	}
	if p&Packet != 0 {
		names = append(names, "packet")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}

type Kind uint8

const (
	KindAdapter Kind = iota
	KindProxy
)

type AddressKind uint8

const (
	AddressHost AddressKind = iota
	AddressPath
	AddressOpaque
)

var ErrInvalidChain = errors.New("invalid chain")

type Options map[string]string

func (o Options) clone() Options {
	c := make(Options, len(o))
	for k, v := range o {
		c[k] = v
	}
	return c
}

type Spec struct {
	Kind           Kind
	Requires       Plane
	Provides       Plane
	Preserves      Plane
	Options        []string
	UsernameOption string
	PasswordOption string
	Adapt          func(inner Transport, opts Options) (Transport, error)
	Client         func(inner Transport, base Network, opts Options) (Network, error)
	Server         func(inner Transport, upstream Network, opts Options) (Server, error)
}

type Server interface {
	Run(ctx context.Context) error
	Close() error
}
