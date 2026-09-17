package permuteproxy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type NetworkSpec struct {
	Plane       Plane
	AddressKind AddressKind
	Network     Network
}

var (
	registryMu sync.RWMutex
	layers     = map[string]Spec{}
	networks   = map[string]NetworkSpec{}
	aliases    = map[string][]string{}
)

func init() {
	RegisterNetwork("tcp", NetworkSpec{Plane: Stream, AddressKind: AddressHost})
	RegisterNetwork("udp", NetworkSpec{Plane: Packet, AddressKind: AddressHost})
	RegisterNetwork("unix", NetworkSpec{Plane: Stream, AddressKind: AddressPath})
	RegisterNetwork("unixgram", NetworkSpec{Plane: Packet, AddressKind: AddressPath})
}

func checkName(name string) {
	if name == "" || strings.Contains(name, "+") {
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

func RegisterNetwork(name string, spec NetworkSpec) {
	registryMu.Lock()
	defer registryMu.Unlock()
	checkName(name)
	if spec.Plane == 0 || spec.Plane&^(Stream|Packet) != 0 || spec.AddressKind > AddressOpaque {
		panic(fmt.Sprintf("permuteproxy: malformed network %q", name))
	}
	networks[name] = spec
}

func RegisterLayer(name string, spec Spec) {
	registryMu.Lock()
	defer registryMu.Unlock()
	checkName(name)
	switch {
	case spec.Requires|spec.Preserves == 0, spec.Provides|spec.Preserves == 0,
		spec.PasswordOption != "" && spec.UsernameOption == "":
		panic(fmt.Sprintf("permuteproxy: malformed layer %q", name))
	case spec.Kind == KindAdapter && (spec.Adapt == nil || spec.Client != nil || spec.Server != nil):
		panic(fmt.Sprintf("permuteproxy: adapter %q must declare only Adapt", name))
	case spec.Kind == KindProxy && (spec.Adapt != nil || (spec.Client == nil && spec.Server == nil)):
		panic(fmt.Sprintf("permuteproxy: proxy %q must declare Client or Server, not Adapt", name))
	case spec.Kind > KindProxy:
		panic(fmt.Sprintf("permuteproxy: unknown kind of layer %q", name))
	}
	spec.Options = append([]string(nil), spec.Options...)
	layers[name] = spec
}

func RegisterAlias(alias, expansion string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	checkName(alias)
	tokens := strings.Split(expansion, "+")
	for _, t := range tokens {
		if t == "" {
			panic(fmt.Sprintf("permuteproxy: malformed alias %q=%q", alias, expansion))
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
