package permuteproxy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// NetworkSpec declares a network: the plane it carries, how a URI writes its address and what implements or expresses it.
type NetworkSpec struct {
	Plane       Plane       // Stream or Packet, the one plane the network carries; left zero with Dial, which derives it
	AddressKind AddressKind // how a URI writes the network's address
	Network     Network     // its implementation; nil leaves tcp, udp, unix and unixgram to the system and others unimplemented
	// Values are quoted for one parse, so a command parsing its arguments again (ssh, sh -c) must not take a path %h.
	Dial   string // expression that dials this network through layers and another network
	Listen string // optional expression for listening
}

var (
	registryMu sync.RWMutex
	layers     = map[string]Spec{}
	networks   = map[string]NetworkSpec{}
	aliases    = map[string][]string{}
	// validName is what url.Parse yields for a lower-cased scheme token, minus the '+' separator.
	validName = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)
)

func init() {
	RegisterNetwork("tcp", NetworkSpec{Plane: Stream, AddressKind: AddressHost})
	RegisterNetwork("udp", NetworkSpec{Plane: Packet, AddressKind: AddressHost})
	RegisterNetwork("unix", NetworkSpec{Plane: Stream, AddressKind: AddressPath})
	RegisterNetwork("unixgram", NetworkSpec{Plane: Packet, AddressKind: AddressPath})
	RegisterNetwork("cmd", NetworkSpec{Plane: Stream, AddressKind: AddressOpaque})
	RegisterLayer("dgram", dgram)
}

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

// ImplementNetwork implements a declared network, panicking on an unknown name, a nil Network or one implemented already.
func ImplementNetwork(name string, n Network) {
	registryMu.Lock()
	defer registryMu.Unlock()
	spec, ok := networks[name]
	switch {
	case !ok:
		panic(fmt.Sprintf("permuteproxy: %q is not a registered network", name))
	case n == nil:
		panic(fmt.Sprintf("permuteproxy: nil implementation of network %q", name))
	case spec.Network != nil:
		panic(fmt.Sprintf("permuteproxy: network %q already has an implementation", name))
	}
	spec.Network = n
	networks[name] = spec
}

// RegisterLayer declares a layer by name, panicking on a malformed spec or a name already taken.
func RegisterLayer(name string, spec Spec) {
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
		spec.PasswordOption != "" && spec.UsernameOption == "":
		panic(fmt.Sprintf("permuteproxy: malformed layer %q", name))
	case spec.Lossy&^Packet != 0, spec.Lossy&^(spec.Provides|spec.Preserves) != 0:
		panic(fmt.Sprintf("permuteproxy: layer %q may mark Lossy only a Packet plane it provides or preserves", name))
	case spec.Kind == KindAdapter && (spec.NewAdapter == nil || spec.NewClient != nil || spec.NewServer != nil):
		panic(fmt.Sprintf("permuteproxy: adapter %q must declare NewAdapter and neither NewClient nor NewServer", name))
	case spec.Kind == KindProxy && (spec.NewAdapter != nil || (spec.NewClient == nil && spec.NewServer == nil)):
		panic(fmt.Sprintf("permuteproxy: proxy %q must declare NewClient or NewServer, not NewAdapter", name))
	case spec.Kind > KindProxy:
		panic(fmt.Sprintf("permuteproxy: unknown kind of layer %q", name))
	case (spec.NewClient == nil) != (len(spec.Networks) == 0):
		panic(fmt.Sprintf("permuteproxy: layer %q must list Networks exactly when it declares NewClient", name))
	}
	spec.Options = append([]string(nil), spec.Options...)
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

func lookupLayer(name string) (Spec, bool) {
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

func expandAliases(tokens []string) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if exp, ok := aliases[t]; ok {
			out = append(out, exp...)
		} else {
			out = append(out, t)
		}
	}
	return out
}

// foldAliases replaces the longest registered expansion found at the head of tokens.
func foldAliases(tokens []string) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		li, lj := len(aliases[names[i]]), len(aliases[names[j]])
		return li > lj || (li == lj && names[i] < names[j])
	})
	for _, name := range names {
		exp := aliases[name]
		if len(exp) <= len(tokens) && strings.Join(tokens[:len(exp)], "+") == strings.Join(exp, "+") {
			return append([]string{name}, tokens[len(exp):]...)
		}
	}
	return tokens
}
