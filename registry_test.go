package permuteproxy

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
)

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic", name)
		}
	}()
	f()
}

func TestRootRegistersNothing(t *testing.T) {
	if len(atRootInit.networks)+len(atRootInit.layers)+len(atRootInit.aliases) != 0 {
		t.Fatalf("the root package itself registers networks %q, layers %q and aliases %q", slices.Sorted(maps.Keys(atRootInit.networks)), slices.Sorted(maps.Keys(atRootInit.layers)), slices.Sorted(maps.Keys(atRootInit.aliases)))
	}
}

func TestRegisterRejects(t *testing.T) {
	adapter := fakeAdapter("x", Stream, Stream)
	mustPanic(t, "duplicate layer", func() { RegisterLayer("test-tls", adapter) })
	mustPanic(t, "layer named like network", func() { RegisterLayer("tcp", adapter) })
	mustPanic(t, "duplicate network", func() { RegisterNetwork("tcp", NetworkSpec{Plane: Stream}) })
	mustPanic(t, "alias named like layer", func() { RegisterAlias("test-tls", "test-http+test-tls") })
	mustPanic(t, "name with plus", func() { RegisterLayer("a+b", adapter) })
	mustPanic(t, "network without plane", func() { RegisterNetwork("np", NetworkSpec{}) })
	mustPanic(t, "adapter without NewAdapter", func() { RegisterLayer("na", LayerSpec{Requires: Stream, Provides: Stream}) })
	mustPanic(t, "proxy with NewAdapter", func() {
		proxy := fakeProxy("pn", Stream, Stream, 0, "", "")
		proxy.NewAdapter = adapter.NewAdapter
		RegisterLayer("pn", proxy)
	})
	mustPanic(t, "layer consuming nothing", func() { RegisterLayer("ln", LayerSpec{Provides: Stream, NewAdapter: adapter.NewAdapter}) })
	mustPanic(t, "password without username", func() {
		RegisterLayer("pw", LayerSpec{Requires: Stream, Provides: Stream, PasswordKey: "p", NewAdapter: adapter.NewAdapter})
	})
	for name, spec := range map[string]LayerSpec{
		"requires":  {Requires: 4, Provides: Stream, NewAdapter: adapter.NewAdapter},
		"provides":  {Requires: Stream, Provides: 4, NewAdapter: adapter.NewAdapter},
		"preserves": {Requires: Stream, Provides: Stream, Preserves: 4, NewAdapter: adapter.NewAdapter},
	} {
		mustPanic(t, "unknown plane bit in "+name, func() { RegisterLayer("bit."+name, spec) })
	}
	for _, name := range []string{"Upper", "cmd_nc", "1bad", "a b", "-x", ".x"} {
		mustPanic(t, "name "+name, func() { RegisterLayer(name, adapter) })
	}
	RegisterLayer(fresh("ok.name"), adapter)
	mustPanic(t, "dual-plane network", func() { RegisterNetwork("dual", NetworkSpec{Plane: Stream | Packet}) })
	mustPanic(t, "nested alias", func() { RegisterAlias("nested", "test-https+tcp") })
	mustPanic(t, "self alias", func() { RegisterAlias("self", "self") })
	mustPanic(t, "alias with malformed token", func() { RegisterAlias("bad", "HTTP+test-tls") })
	mustPanic(t, "alias named like an expansion token", func() { RegisterAlias("pending", "test-snappy") })
	for _, name := range []string{"na", "pn"} {
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
}

func TestRegisterRejectsClientDeclarations(t *testing.T) {
	proxy := fakeProxy("pc", Stream, Stream, 0, "", "")
	unlisted, listed, unknown, variant, adapter := proxy, proxy, proxy, proxy, fakeAdapter("ac", Stream, Stream)
	unlisted.Networks = nil
	listed.NewClient = nil
	unknown.Networks = []string{"tcp", "bogus"}
	variant.Networks = []string{"udp", "tcp4"}
	adapter.NewClient, adapter.Networks = proxy.NewClient, proxy.Networks
	for name, spec := range map[string]LayerSpec{
		"client-unlisted": unlisted,
		"client-listed":   listed,
		"client-unknown":  unknown,
		"client-variant":  variant,
		"client-adapter":  adapter,
	} {
		mustPanic(t, name, func() { RegisterLayer(name, spec) })
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
}

func TestRegisterRejectsServerDeclarations(t *testing.T) {
	proxy := fakeProxy("ps", Stream, Stream, 0, "", "")
	adapter := fakeAdapter("as", Stream, Stream)
	adapter.NewServer = proxy.NewServer
	for name, spec := range map[string]LayerSpec{
		"server-adapter": adapter,
		"server-none":    {Kind: LayerProxy, Requires: Stream, Provides: Stream},
	} {
		mustPanic(t, name, func() { RegisterLayer(name, spec) })
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
}

func TestRegisterLossy(t *testing.T) {
	newAdapter := fakeAdapter("x", Stream, Stream).NewAdapter
	for name, spec := range map[string]LayerSpec{
		"lossy-stream":    {Requires: Stream, Provides: Stream | Packet, Lossy: Stream, NewAdapter: newAdapter},
		"lossy-both":      {Requires: Stream, Provides: Stream | Packet, Lossy: Stream | Packet, NewAdapter: newAdapter},
		"lossy-bit":       {Requires: Stream, Provides: Packet, Lossy: 4, NewAdapter: newAdapter},
		"lossy-unoffered": {Requires: Packet, Provides: Stream, Lossy: Packet, NewAdapter: newAdapter},
	} {
		mustPanic(t, name, func() { RegisterLayer(name, spec) })
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
	RegisterLayer(fresh("lossy-provided"), LayerSpec{Requires: Stream, Provides: Packet, Lossy: Packet, NewAdapter: newAdapter})
	RegisterLayer(fresh("lossy-preserved"), LayerSpec{Requires: Stream, Provides: Stream, Preserves: Packet, Lossy: Packet, NewAdapter: newAdapter})
}

func TestRegisterCopiesNetworks(t *testing.T) {
	calls = nil
	networks := []string{"tcp"}
	spec := fakeProxy("test-copied", Stream, Stream, 0, "", "")
	spec.Networks = networks
	name := fresh("test-copied")
	RegisterLayer(name, spec)
	networks[0] = "unix"
	n, err := ClientEngine{Base: &fakeNet{name: "base"}}.Client(mk("", name))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := n.DialContext(context.Background(), "unix", "x:1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unix dial after the caller changed its slice = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
}
