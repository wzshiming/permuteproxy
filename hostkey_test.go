package permuteproxy

import (
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// named records the options each test-named adapter was built with, innermost first.
var named struct {
	sync.Mutex
	opts []Options
}

func init() {
	RegisterLayer("test-named", LayerSpec{
		Requires:   Stream,
		Provides:   Stream,
		OptionKeys: []string{"other"},
		HostKey:    "name",
		NewAdapter: func(opts Options) (*AdapterFuncs, error) {
			named.Lock()
			named.opts = append(named.opts, opts)
			named.Unlock()
			return &AdapterFuncs{Stream: &Link{}}, nil
		},
	})
	// The expression dials a relay of its own, whatever host the chain names.
	RegisterNetwork("test-relayed", NetworkSpec{AddressKind: AddressHost, Dial: "test-named+tcp://relay.test:%p"})
	RegisterNetwork("test-wrapped", NetworkSpec{AddressKind: AddressPath, Dial: "test-named+cmd:reach %h"})
}

func namedOptions(t *testing.T, build func() (any, error)) []Options {
	t.Helper()
	named.Lock()
	named.opts = nil
	named.Unlock()
	built, err := build()
	if err != nil {
		t.Fatal(err)
	}
	closeIf(built)
	named.Lock()
	defer named.Unlock()
	return named.opts
}

func TestHostKeyDefaultsToTheEndpointHost(t *testing.T) {
	tests := []struct {
		name  string
		chain Chain
		want  []Options
	}{
		{"name", parse(t, "test-named://proxy.test:8443"), []Options{{"name": "proxy.test"}}},
		{"explicit network", parse(t, "test-named+tcp://proxy.test:8443"), []Options{{"name": "proxy.test"}}},
		{"other options kept", parse(t, "test-named://proxy.test:8443?other=x"), []Options{{"name": "proxy.test", "other": "x"}}},
		{"set", parse(t, "test-named://proxy.test:8443?name=other.test"), []Options{{"name": "other.test"}}},
		{"set empty", parse(t, "test-named://proxy.test:8443?name="), []Options{{"name": ""}}},
		{"every layer", parse(t, "test-named+test-snappy+test-named://proxy.test:8443"), []Options{{"name": "proxy.test"}, {"name": "proxy.test"}}},
		{"ipv4", parse(t, "test-named://127.0.0.1:8443"), []Options{{"name": "127.0.0.1"}}},
		{"ipv6", parse(t, "test-named://[::1]:8443"), []Options{{"name": "::1"}}},
		{"ipv6 zone", Chain{Layers: []Layer{{Scheme: "test-named"}}, Endpoint: Endpoint{Address: "[fe80::1%eth0]:8443"}}, []Options{{"name": "fe80::1"}}},
		{"no host", Chain{Layers: []Layer{{Scheme: "test-named"}}, Endpoint: Endpoint{Address: ":8443"}}, []Options{{}}},
		{"unix path", Chain{Layers: []Layer{{Scheme: "test-named"}}, Endpoint: Endpoint{Network: "unix", Address: "/run/proxy.test:8443"}}, []Options{{}}},
		{"command line", Chain{Layers: []Layer{{Scheme: "test-named"}}, Endpoint: Endpoint{Network: "cmd", Address: "nc proxy.test:8443"}}, []Options{{}}},
		{"expression layers take the endpoint they dial", parse(t, "test-named+test-relayed://proxy.test:8443"), []Options{{"name": "relay.test"}, {"name": "proxy.test"}}},
		{"expression over a command", Chain{Layers: []Layer{{Scheme: "test-named"}}, Endpoint: Endpoint{Network: "test-wrapped", Address: "/run/proxy.sock"}}, []Options{{}, {}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before []Options
			for _, l := range tt.chain.Layers {
				before = append(before, l.Options.clone())
			}
			got := namedOptions(t, func() (any, error) { return TransportEngine{Base: &fakeNet{name: "base"}}.Transport(tt.chain) })
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("options (-want +got):\n%s", diff)
			}
			for i, l := range tt.chain.Layers {
				if diff := cmp.Diff(before[i], l.Options.clone()); diff != "" {
					t.Fatalf("chain mutated by build (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestHostKeyUnderAProxy(t *testing.T) {
	c := parse(t, "test-http+test-named://proxy.test:8443")
	want := []Options{{"name": "proxy.test"}}
	got := namedOptions(t, func() (any, error) { return ClientEngine{Base: &fakeNet{name: "base"}}.Client(c) })
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("client options (-want +got):\n%s", diff)
	}
	got = namedOptions(t, func() (any, error) { return ServerEngine{Base: &fakeNet{name: "base"}}.Server(c) })
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("server options (-want +got):\n%s", diff)
	}
}

func TestHostKeyIsForAdapters(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RegisterLayer took a proxy with a HostKey")
		}
	}()
	spec := fakeProxy("test-named-proxy", Stream, Stream, 0, "username", "password")
	spec.HostKey = "name"
	RegisterLayer("test-named-proxy", spec)
}
