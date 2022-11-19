package netutils

import (
	"net"
)
 
func NewNetAddr(network, address string) net.Addr {
	return &addr{network: network, address: address}
}

type addr struct {
	network string
	address string
}

func (a *addr) Network() string {
	return a.network
}
func (a *addr) String() string {
	return a.address
}
