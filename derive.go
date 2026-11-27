package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// derivable are the base networks a client may derive, those the root package declares but unixgram, whose local end is a path.
var derivable = []string{"tcp", "udp", "unix", "cmd"}

// derivation is a base network a client derives by expression from the networks it lists.
type derivation struct {
	network string
	kind    AddressKind
	plane   Plane
	lossy   bool // its expression loses datagram boundaries, as through dgram
	x       expression
}

// derive checks each network exprs derives for a client of s.
func (s LayerSpec) derive(exprs map[string]string) (map[string]derivation, error) {
	derived := map[string]derivation{}
	for _, network := range slices.Sorted(maps.Keys(exprs)) {
		switch {
		case !slices.Contains(derivable, network):
			return nil, fmt.Errorf("network %q in Derive: not one of the base networks %q", network, derivable)
		case slices.Contains(s.Networks, network):
			return nil, fmt.Errorf("network %q in Derive: also listed in Networks", network)
		}
		ns, _ := lookupNetwork(network)
		x, err := checkExpression(exprs[network], ns.AddressKind)
		if err != nil {
			return nil, fmt.Errorf("network %q in Derive: %w", network, err)
		}
		if !slices.Contains(s.Networks, x.network) {
			return nil, fmt.Errorf("network %q in Derive: %q is not listed in Networks", network, x.network)
		}
		planes, lossy, err := x.offers()
		switch {
		case err != nil:
			return nil, fmt.Errorf("network %q in Derive: %w", network, err)
		case planes&ns.Plane == 0:
			return nil, fmt.Errorf("network %q in Derive: the expression offers %v, not %v", network, planes, ns.Plane)
		}
		derived[network] = derivation{network: network, kind: ns.AddressKind, plane: ns.Plane, lossy: lossy&ns.Plane != 0, x: x}
	}
	return derived, nil
}

// dialContext dials a derived stream network at once, a derived datagram network on the first Write to address.
func (d derivation) dialContext(ctx context.Context, a *assembledNetwork, address string) (net.Conn, error) {
	if d.plane == Stream {
		return d.dial(ctx, a, address)
	}
	if _, err := d.x.expand(d.kind, address); err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", d.network, address, err)
	}
	pc, err := d.sessions(a)
	if err != nil {
		return nil, err
	}
	return netutils.WrapPacket(pc, netutils.NewNetAddr(d.network, address)), nil
}

// listenPacket binds a derived datagram network, which has no local end of its own to bind at a chosen address.
func (d derivation) listenPacket(a *assembledNetwork, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "0" || host != "" && !net.ParseIP(host).IsUnspecified() {
		return nil, fmt.Errorf("listen packet %s %s: binds only an unspecified host with port 0: %w", d.network, address, ErrUnsupported)
	}
	return d.sessions(a)
}

// sessions reaches each peer over a dial of its own.
func (d derivation) sessions(a *assembledNetwork) (net.PacketConn, error) {
	a.mu.RLock()
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return nil, fmt.Errorf("%s: %w", d.network, net.ErrClosed)
	}
	return netutils.NewSessions(func(ctx context.Context, peer net.Addr) (net.Conn, error) {
		return d.dial(ctx, a, peer.String())
	}, netutils.SessionOptions{}), nil
}

// dial builds d's expression for address over a and dials the derived plane; the conn's Close releases what it built.
func (d derivation) dial(ctx context.Context, a *assembledNetwork, address string) (net.Conn, error) {
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return nil, fmt.Errorf("dial %s %s: %w", d.network, address, net.ErrClosed)
	}
	a.dials.Add(1)
	a.mu.RUnlock()
	defer a.dials.Done()
	text, err := d.x.expand(d.kind, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", d.network, address, err)
	}
	tr, err := TransportEngine{Base: a}.Transport(d.x.over(text))
	if err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, d.plane)
	if err != nil {
		closeIf(tr)
		return nil, err
	}
	return netutils.ConnWithCloser(conn, sync.OnceValue(func() error { return errors.Join(conn.Close(), closeIf(tr)) })), nil
}
