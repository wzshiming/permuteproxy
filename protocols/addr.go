package protocols

type addr struct {
	network string
	address string
}

func NewAddr(network string, address string) Addr {
	return &addr{
		network: network,
		address: address,
	}
}

func (a *addr) Network() string {
	return a.network
}

func (a *addr) String() string {
	return a.address
}
