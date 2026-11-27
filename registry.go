package permuteproxy

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Options are a layer's option values by name.
type Options map[string]string

func (o Options) clone() Options {
	c := make(Options, len(o))
	for k, v := range o {
		c[k] = v
	}
	return c
}

// LayerSpec declares a layer, the planes it consumes and offers, its options and constructors: NewAdapter makes it an adapter, which turns its carrier into the planes of the layer above, as tls does; NewClient or NewServer make it a proxy, which serves or dials a proxy protocol as the outermost layer, as socks5 does.
type LayerSpec struct {
	Requires    Plane                                     // planes the carrier must have, or the chain is invalid; requiring one does not offer it above
	Provides    Plane                                     // planes offered above whatever the carrier has
	Preserves   Plane                                     // carrier planes also offered above, but only those the carrier has
	Lossy       Plane                                     // planes the layer provides without datagram boundaries
	OptionKeys  []string                                  // names of the options the layer accepts
	UsernameKey string                                    // optional; the option a URI's username fills
	PasswordKey string                                    // optional; the option a URI's password fills, beside UsernameKey
	HostKey     string                                    // optional, adapters only; the option a build fills with the host of a host:port endpoint when the layer does not set it, as tls names the server it dials
	NewAdapter  func(opts Options) (*AdapterFuncs, error) // declares an adapter's links per build
	Networks    []string                                  // base networks the layer's client accepts: tcp, udp, unix, unixgram, ...
	NewClient   func(opts Options) (*ClientFuncs, error)  // declares a proxy's client per build
	NewServer   func(opts Options) (*ServerFuncs, error)  // declares a proxy's server per build
}

// isProxy reports whether s speaks a proxy protocol as the outermost layer, as socks5 does, rather than adapting its carrier, as tls does.
func (s LayerSpec) isProxy() bool {
	return s.NewAdapter == nil
}

func (s LayerSpec) accepts(key string) bool {
	if key == "" {
		return false
	}
	if key == s.UsernameKey || key == s.PasswordKey || key == s.HostKey {
		return true
	}
	for _, o := range s.OptionKeys {
		if o == key {
			return true
		}
	}
	return false
}

// NetworkSpec declares a network: the plane it carries, how a URI writes its address and what implements or expresses it.
type NetworkSpec struct {
	Plane       Plane       // Stream or Packet, the one plane the network carries; left zero with Dial, which derives it
	AddressKind AddressKind // how a URI writes the network's address
	Network     Network     // its implementation, what an engine's nil Base, Local or Upstream resolves the name to; nil leaves it unimplemented
	Dial        string      // expression that dials this network through layers and another network, its values quoted for one parse, so a command parsing them again (ssh, sh -c) must not take a path %h
	Listen      string      // optional expression for listening
	// NewClient, when set, makes a chain of this network alone a client, as nc:ssh jump is: it
	// builds the client over base, which reaches the endpoint, from the chain's address, which may be empty.
	NewClient func(base Network, address string) (Network, error)
}

// AddressKind says how a URI writes a network's address.
type AddressKind uint8

const (
	AddressHost   AddressKind = iota // host:port in the authority, as tcp://127.0.0.1:1080
	AddressPath                      // a path across the authority and path, as unix://./proxy.sock
	AddressOpaque                    // free text after the scheme, as cmd:nc host 1080
)

var (
	registryMu sync.RWMutex
	layers     = map[string]LayerSpec{}
	networks   = map[string]NetworkSpec{}
	aliases    = map[string][]string{}
	// validName is what url.Parse yields for a lower-cased scheme token, minus the '+' separator.
	validName = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)
)

func checkName(name string) {
	if !validName.MatchString(name) {
		panic(fmt.Sprintf("permuteproxy: malformed name %q", name))
	}
	if _, ok := layers[name]; ok {
		panic(fmt.Sprintf("permuteproxy: %q already registered as layer", name))
	}
	if _, ok := networks[name]; ok {
		panic(fmt.Sprintf("permuteproxy: %q already registered as network", name))
	}
	if _, ok := aliases[name]; ok {
		panic(fmt.Sprintf("permuteproxy: %q already registered as alias", name))
	}
}

// RegisterNetwork declares a network by name, its plane derived from Dial when set, panicking on a malformed spec or a name already taken.
func RegisterNetwork(name string, spec NetworkSpec) {
	if spec.Dial != "" || spec.Listen != "" {
		// The expressions are looked up under the registry lock, so they are checked before RegisterNetwork holds it.
		plane, err := expressionPlane(spec)
		if err != nil {
			panic(fmt.Sprintf("permuteproxy: network %q: %v", name, err))
		}
		spec.Plane = plane
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	checkName(name)
	if spec.Plane != Stream && spec.Plane != Packet || spec.AddressKind > AddressOpaque {
		panic(fmt.Sprintf("permuteproxy: malformed network %q", name))
	}
	networks[name] = spec
}

// RegisterLayer declares a layer by name, panicking on a malformed spec or a name already taken.
func RegisterLayer(name string, spec LayerSpec) {
	// lookupBase takes the registry lock, so Networks are checked before RegisterLayer holds it.
	for _, network := range spec.Networks {
		if base, _, ok := lookupBase(network); !ok || base != network {
			panic(fmt.Sprintf("permuteproxy: layer %q lists %q, not a registered base network", name, network))
		}
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	checkName(name)
	switch {
	case spec.Requires|spec.Preserves == 0, spec.Provides|spec.Preserves == 0,
		(spec.Requires|spec.Provides|spec.Preserves)&^(Stream|Packet) != 0,
		spec.PasswordKey != "" && spec.UsernameKey == "":
		panic(fmt.Sprintf("permuteproxy: malformed layer %q", name))
	case spec.Lossy&^Packet != 0, spec.Lossy&^(spec.Provides|spec.Preserves) != 0:
		panic(fmt.Sprintf("permuteproxy: layer %q may mark Lossy only a Packet plane it provides or preserves", name))
	case spec.NewAdapter != nil && (spec.NewClient != nil || spec.NewServer != nil):
		panic(fmt.Sprintf("permuteproxy: layer %q must declare either NewAdapter, as an adapter, or NewClient or NewServer, as a proxy, not both", name))
	case spec.HostKey != "" && spec.NewAdapter == nil:
		panic(fmt.Sprintf("permuteproxy: layer %q may set HostKey only as an adapter", name))
	case spec.NewAdapter == nil && spec.NewClient == nil && spec.NewServer == nil:
		panic(fmt.Sprintf("permuteproxy: layer %q must declare NewAdapter, as an adapter, or NewClient or NewServer, as a proxy", name))
	case (spec.NewClient == nil) != (len(spec.Networks) == 0):
		panic(fmt.Sprintf("permuteproxy: layer %q must list Networks exactly when it declares NewClient", name))
	}
	spec.OptionKeys = append([]string(nil), spec.OptionKeys...)
	spec.Networks = append([]string(nil), spec.Networks...)
	layers[name] = spec
}

// RegisterAlias names a '+'-joined run of tokens that ParseURI expands and URI folds back, panicking on a malformed or nested alias or a name already taken.
func RegisterAlias(alias, expansion string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	checkName(alias)
	tokens := strings.Split(expansion, "+")
	for _, t := range tokens {
		if _, nested := aliases[t]; nested || t == alias || !validName.MatchString(t) {
			panic(fmt.Sprintf("permuteproxy: malformed alias %q=%q", alias, expansion))
		}
	}
	for name, exp := range aliases {
		for _, t := range exp {
			if t == alias {
				panic(fmt.Sprintf("permuteproxy: alias %q is expanded by alias %q", alias, name))
			}
		}
	}
	aliases[alias] = tokens
}

func lookupLayer(name string) (LayerSpec, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	spec, ok := layers[name]
	return spec, ok
}

func lookupNetwork(name string) (NetworkSpec, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	spec, ok := networks[name]
	return spec, ok
}

// lookupBase maps a network name to its registered base name and plane; tcp4 / tcp6 and udp4 / udp6 are tcp and udp.
func lookupBase(network string) (string, Plane, bool) {
	switch network {
	case "tcp4", "tcp6":
		network = "tcp"
	case "udp4", "udp6":
		network = "udp"
	}
	ns, ok := lookupNetwork(network)
	return network, ns.Plane, ok
}
