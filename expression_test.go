package permuteproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// The expression fixtures are registered after chain_test.go's, so they may name its layers and networks.
func init() {
	RegisterNetwork("test-nc", NetworkSpec{AddressKind: AddressHost, Dial: "cmd:nc %h %p", Listen: "cmd:nc -l %h %p"})
	RegisterNetwork("test-nc-unix", NetworkSpec{AddressKind: AddressPath, Dial: "cmd:nc -U %h", Network: &fakeNet{name: "impl"}})
	RegisterNetwork("test-nc-udp", NetworkSpec{AddressKind: AddressHost, Dial: "dgram+cmd:nc -u -w 30 %h %p"})
	RegisterNetwork("test-cmd-packet", NetworkSpec{AddressKind: AddressOpaque, Dial: "dgram+cmd:%a"})
	// test-auth takes an option and a username, which a URI must never hand to an expression's layer.
	auth := fakeAdapter("test-auth", Stream, Stream, "opt")
	auth.UsernameKey = "username"
	RegisterLayer("test-auth", auth)
	RegisterNetwork("test-auth-tcp", NetworkSpec{AddressKind: AddressHost, Dial: "test-auth+tcp://%h:%p", Listen: "test-auth+tcp://0.0.0.0:%p"})
	RegisterNetwork("test-snappy-unix", NetworkSpec{AddressKind: AddressPath, Dial: "test-snappy+unix://%h"})
	RegisterNetwork("test-percent", NetworkSpec{AddressKind: AddressHost, Dial: "cmd:printf %%h:%%p %h:%p"})
	RegisterNetwork("test-closable-tcp", NetworkSpec{AddressKind: AddressHost, Dial: "closable+tcp://%h:%p"})
	RegisterNetwork("test-via-fakenet", NetworkSpec{AddressKind: AddressHost, Dial: "fakenet://%h:%p"})
	RegisterNetwork("test-dtls-udp", NetworkSpec{AddressKind: AddressHost, Dial: "test-dtls+udp://%h:%p"})
	RegisterNetwork("test-abs-nc", NetworkSpec{AddressKind: AddressHost, Dial: "cmd:/usr/bin/nc %h %p #?"})
}

// carrierNet is fakeNet dialing conns that name their peer, which dgram reads.
type carrierNet struct{ fakeNet }

func (n *carrierNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	n.fakeNet.DialContext(ctx, network, address)
	return netutils.ConnWithAddr(nil, nil, netutils.NewNetAddr(network, address)), nil
}

func TestRegisterNetworkDerivesPlaneFromDial(t *testing.T) {
	for name, want := range map[string]Plane{
		"test-nc":         Stream,
		"test-nc-unix":    Stream,
		"test-nc-udp":     Packet,
		"test-cmd-packet": Packet,
	} {
		if ns, ok := lookupNetwork(name); !ok || ns.Plane != want {
			t.Fatalf("%s: registered %v with plane %v, want %v", name, ok, ns.Plane, want)
		}
	}
}

// panicked runs f and returns what it panicked with, or "" when it returned.
func panicked(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func TestRegisterNetworkRejectsExpressions(t *testing.T) {
	host := func(dial, listen string) NetworkSpec {
		return NetworkSpec{AddressKind: AddressHost, Dial: dial, Listen: listen}
	}
	tests := []struct {
		name string
		spec NetworkSpec
		want string // what the panic names
	}{
		{"no scheme", host("nc %h %p", ""), "unparsable"},
		{"empty scheme", host(":nc %h %p", ""), "unparsable"},
		{"empty layer", host("+cmd:nc %h %p", ""), "unparsable"},
		{"malformed token", host("Cmd:nc %h %p", ""), "unparsable"},
		{"empty template", host("cmd:", ""), "unparsable"},
		{"control character in template", host("cmd:nc\t%h %p", ""), "unparsable"},
		{"authority over an opaque network", host("cmd://nc %h %p", ""), "unparsable"},
		{"opaque over a host network", host("tcp:%h:%p", ""), "unparsable"},
		{"unknown layer", host("bogus+cmd:nc %h %p", ""), `"bogus" is not a registered adapter`},
		{"proxy layer", host("test-http+cmd:nc %h %p", ""), `"test-http" is not a registered adapter`},
		{"unknown network", host("bogus:nc %h %p", ""), `"bogus" is not a registered network`},
		{"layer as network", host("dgram:nc %h %p", ""), `"dgram" is not a registered network`},
		{"network declared by expression", host("test-nc://%h:%p", ""), `"test-nc" is itself declared by expression`},
		{"%a for a host address", host("cmd:nc %a", ""), `placeholder "%a"`},
		{"%p for a path address", NetworkSpec{AddressKind: AddressPath, Dial: "cmd:nc -U %h %p"}, `placeholder "%p"`},
		{"%h for an opaque address", NetworkSpec{AddressKind: AddressOpaque, Dial: "cmd:%h"}, `placeholder "%h"`},
		{"unknown placeholder", host("cmd:nc %h %x", ""), `placeholder "%x"`},
		{"lone percent", host("cmd:nc %h %p %", ""), `placeholder "%"`},
		{"placeholder in single quotes", host("cmd:sh -c 'exec nc %h %p'", ""), `placeholder "%h" is inside quotes`},
		{"placeholder in double quotes", host(`cmd:sh -c "exec nc %h %p"`, ""), `placeholder "%h" is inside quotes`},
		{"path placeholder in quotes", NetworkSpec{AddressKind: AddressPath, Dial: `cmd:sh -c 'printf "<%%s>" %h'`}, `placeholder "%h" is inside quotes`},
		{"placeholder after command substitution", host(`cmd:sh -c "$(printf "nc %h %p")"`, ""), `placeholder "%h" follows "$"`},
		{"placeholder after arithmetic expansion", host("cmd:echo $[ %h ] %p", ""), `placeholder "%h" follows "$"`},
		{"placeholder next to a redirection", host("cmd:nc %h %p>x", ""), `placeholder "%p" is next to ">"`},
		{"layer requiring a plane the network lacks", host("test-quic+cmd:nc %h %p", ""), `"test-quic" requires`},
		{"packet required over lossy datagrams", host("test-dtls+dgram+cmd:nc %h %p", ""), "datagram boundaries"},
		{"plane with dial", NetworkSpec{Plane: Stream, AddressKind: AddressHost, Dial: "cmd:nc %h %p"}, "Plane set with Dial"},
		{"listen without dial", NetworkSpec{Plane: Stream, AddressKind: AddressHost, Listen: "cmd:nc -l %h %p"}, "Listen without Dial"},
		{"listen with other layers", host("dgram+cmd:nc -u %h %p", "cmd:nc -u -l %h %p"), "Listen differs from Dial"},
		{"listen over another network", host("cmd:nc %h %p", "test-cmd:nc -l %h %p"), "Listen differs from Dial"},
		{"unparsable listen", host("cmd:nc %h %p", "nc -l %h %p"), "Listen: unparsable"},
		{"listen with unknown placeholder", host("cmd:nc %h %p", "cmd:nc -l %h %x"), `Listen: placeholder "%x"`},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := fmt.Sprintf("test-rejected-%d", i)
			if msg := panicked(func() { RegisterNetwork(name, tt.spec) }); !strings.Contains(msg, tt.want) {
				t.Fatalf("RegisterNetwork panicked with %q, want it to name %s", msg, tt.want)
			}
			if _, ok := lookupNetwork(name); ok {
				t.Fatalf("rejected network %q was registered", name)
			}
		})
	}
}

func TestExpressionRefusesPlaceholdersAShellReadsQuoted(t *testing.T) {
	for template, refused := range map[string]bool{
		`cmd:sh -c 'exec nc "$0" "$1"' %h %p`: false,
		`cmd:printf '%%s' \' "it's" %h %p`:    false,
		`cmd:printf 'a\' %h %p`:               false,
		`cmd:printf "a\\" %h %p`:              false,
		`cmd:nc %h %p \`:                      false,
		`cmd:printf "a\" %h" %p`:              true,
		`cmd:printf "a\" %h"`:                 true,
		`cmd:printf "\%h" %p`:                 true,
		`cmd:nc '%h' %p`:                      true,
		`cmd:nc \%h %p`:                       true,
		`cmd:printf %%s "$(echo "a %h")"`:     true,
		`cmd:printf %%s "${x:-"a %h"}"`:       true,
		"cmd:printf %%s \"`echo \"a %h\"`\"":  true,
		`cmd:printf %%s $'it\'s %h'`:          true,
		`cmd:printf '$(' %h`:                  false,
		`cmd:printf "([{" %h`:                 false,
		`cmd:printf "$'" %h`:                  true,
		`cmd:printf %%s "$(echo " %h ")"`:     true,
	} {
		if _, err := checkExpression(template, AddressHost); (err != nil) != refused {
			t.Fatalf("checkExpression(%q) = %v, want refused: %v", template, err, refused)
		}
	}
}

func TestExpressionAcceptsCommandPlaceholdersOnlyAmongInertBytes(t *testing.T) {
	for _, tt := range []struct {
		template string
		kind     AddressKind
		refused  bool
	}{
		{"cmd:nc %h %p", AddressHost, false},
		{"cmd:nc -l %h %p", AddressHost, false},
		{"cmd:nc -U %h", AddressPath, false},
		{"cmd:nc -Ul %h", AddressPath, false},
		{"dgram+cmd:nc -u -w 30 %h %p", AddressHost, false},
		{"cmd:/usr/bin/nc %h %p #?", AddressHost, false},
		{"cmd:socat - UDP:%h:%p", AddressHost, false},
		{"cmd:relay host=%h port=%p", AddressHost, false},
		// every inert byte group but blank, colon and equals stands next to a placeholder
		{"cmd:relay a%h+%p,%h-%p.%h/%p@%h_%p%%%h0 Z%p", AddressHost, false},
		{"dgram+cmd:%a", AddressOpaque, false},
		{"cmd:(%a)", AddressOpaque, false},
		{"tcp://[%h]:%p", AddressHost, false},
		{"unix:///tmp/it's/%h", AddressPath, false},
		{"cmd:echo $[ %h ]", AddressHost, true},
		{"cmd:(( %h ))", AddressHost, true},
		{"cmd:echo $%h", AddressPath, true},
		{"cmd:[[ %h -eq 0 ]]", AddressHost, true},
		{"cmd:a[%h]=1", AddressHost, true},
		{"cmd:{ nc %h %p; }", AddressHost, true},
		{"cmd:echo {a,%h,b}", AddressPath, true},
		{"cmd:`which nc` -U %h", AddressPath, true},
		{"cmd:printf %%s %h</dev/null", AddressPath, true},
		{"cmd:printf %%s %h>/dev/null", AddressPath, true},
		{"cmd:nc ~%h", AddressPath, true},
	} {
		if _, err := checkExpression(tt.template, tt.kind); (err != nil) != tt.refused {
			t.Errorf("checkExpression(%q) = %v, want refused: %v", tt.template, err, tt.refused)
		}
	}
}

func TestExpressionNetworkRoundTrips(t *testing.T) {
	tests := []struct {
		uri  string
		want Chain
	}{
		{"test-nc://127.0.0.1:1", Chain{Endpoint: Endpoint{Network: "test-nc", Address: "127.0.0.1:1"}}},
		{
			"test-http+test-nc://u:p@127.0.0.1:1",
			Chain{Layers: []Layer{{Scheme: "test-http", Options: Options{"username": "u", "password": "p"}}}, Endpoint: Endpoint{Network: "test-nc", Address: "127.0.0.1:1"}},
		},
		{"test-nc-udp://[fe80::1%25en0]:53", Chain{Endpoint: Endpoint{Network: "test-nc-udp", Address: "[fe80::1%en0]:53"}}},
		{"test-nc-unix:///tmp/a%20b.sock", Chain{Endpoint: Endpoint{Network: "test-nc-unix", Address: "/tmp/a b.sock"}}},
		{"test-cmd-packet:nc -u host 53", Chain{Endpoint: Endpoint{Network: "test-cmd-packet", Address: "nc -u host 53"}}},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got, err := ParseURI(tt.uri)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("ParseURI mismatch (-want +got):\n%s", diff)
			}
			if back, err := got.URI(); err != nil || back != tt.uri {
				t.Fatalf("URI() = %q, %v; want %q", back, err, tt.uri)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var again Chain
			if err := json.Unmarshal(data, &again); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(got, again); diff != "" {
				t.Fatalf("json roundtrip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseURIKeepsOptionsOffExpressionLayers(t *testing.T) {
	for _, uri := range []string{"test-auth-tcp://127.0.0.1:1?opt=1", "test-auth-tcp://u@127.0.0.1:1"} {
		if _, err := ParseURI(uri); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("ParseURI(%q) = %v, want ErrInvalidChain since the chain lists no layer taking it", uri, err)
		}
	}
	want := Chain{Layers: []Layer{{Scheme: "test-auth", Options: Options{"username": "u", "opt": "1"}}}, Endpoint: Endpoint{Network: "test-auth-tcp", Address: "127.0.0.1:1"}}
	if diff := cmp.Diff(want, parse(t, "test-auth+test-auth-tcp://u@127.0.0.1:1?opt=1")); diff != "" {
		t.Fatalf("ParseURI mismatch (-want +got):\n%s", diff)
	}
}

func TestChainValidateExpandsExpression(t *testing.T) {
	over := func(network, address string, schemes ...string) Chain {
		c := Chain{Endpoint: Endpoint{Network: network, Address: address}}
		for _, s := range schemes {
			c.Layers = append(c.Layers, Layer{Scheme: s})
		}
		return c
	}
	tests := []struct {
		name  string
		chain Chain
		names []string // what the error names; nil for a valid chain
	}{
		{"lossy datagrams outermost", over("test-nc-udp", "127.0.0.1:1"), nil},
		{"stream layer over a stream expression", over("test-nc", "127.0.0.1:1", "test-tls"), nil},
		{"packet required over an expression through dgram", over("test-nc-udp", "127.0.0.1:1", "test-dtls"), []string{`"test-dtls"`, "datagram boundaries"}},
		{"packet required over an opaque expression through dgram", over("test-cmd-packet", "nc -u host 53", "test-dtls"), []string{`"test-dtls"`, "datagram boundaries"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.chain.Validate()
			if tt.names == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want a valid chain", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Validate() = %v, want ErrInvalidChain", err)
			}
			for _, name := range tt.names {
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("Validate() = %v, want it to name %s", err, name)
				}
			}
		})
	}
	if _, err := ParseURI("test-dtls+test-nc-udp://127.0.0.1:1"); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("ParseURI with Packet required over an expression through dgram = %v, want ErrInvalidChain", err)
	}
}

func TestResolveLeavesTheChainsSpareLayers(t *testing.T) {
	layers := append(make([]Layer, 0, 2), Layer{Scheme: "test-tls"})
	spare := layers[:2]
	spare[1] = Layer{Scheme: "spare"}
	if err := (Chain{Layers: layers, Endpoint: Endpoint{Network: "test-auth-tcp", Address: "127.0.0.1:1"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if spare[1].Scheme != "spare" {
		t.Fatalf("resolve wrote %q into the spare capacity of the chain's Layers", spare[1].Scheme)
	}
}

func TestResolveValidatesExpressionValues(t *testing.T) {
	tests := []struct {
		network string
		address string
		ok      bool
	}{
		{"test-nc", "127.0.0.1:1", true},
		{"test-nc", "[fe80::1%en0]:65535", true},
		{"test-nc", "my_host.example-1:80", true},
		{"test-nc", ":1", true},
		{"test-nc", "127.0.0.1:0", true},
		{"test-nc", "127.0.0.1", false},
		{"test-nc", "-oProxyCommand=x:1", false},
		{"test-nc", "-h:1", false},
		{"test-nc", "[--help]:1", false},
		{"test-nc", "a=b:1", false},
		{"test-nc", "a,b:1", false},
		{"test-nc", "a b:1", false},
		{"test-nc", "a;b:1", false},
		{"test-nc", "a/b:1", false},
		{"test-nc", "é:1", false},
		{"test-nc", "h:65536", false},
		{"test-nc", "h:+1", false},
		{"test-nc", "h:x", false},
		{"test-nc", "h:", false},
		{"test-nc", strings.Repeat("a", 255) + ":1", true},
		{"test-nc", strings.Repeat("a", 256) + ":1", false},
		{"test-nc-unix", "/tmp/a b.sock", true},
		{"test-nc-unix", "./é.sock", true},
		{"test-nc-unix", "-x.sock", false},
		{"test-nc-unix", "/tmp/a\nb.sock", false},
		{"test-nc-unix", "/tmp/a\x7fb.sock", false},
		{"test-nc-unix", "/tmp/a\u0085b.sock", false},
		{"test-nc-unix", "/tmp/\xff.sock", false},
		{"test-cmd-packet", "nc -u host 53", true},
	}
	for _, tt := range tests {
		t.Run(tt.network+" "+tt.address, func(t *testing.T) {
			err := Chain{Endpoint: Endpoint{Network: tt.network, Address: tt.address}}.Validate()
			if tt.ok && err != nil {
				t.Fatalf("Validate() = %v, want the value accepted", err)
			}
			if !tt.ok && !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Validate() = %v, want ErrInvalidChain", err)
			}
		})
	}
}

// A chain refuses an empty address before expanding it, so the expander's own refusal shows only when called directly.
func TestExpandRefusesEmptyValues(t *testing.T) {
	for _, tt := range []struct {
		expression string
		kind       AddressKind
	}{
		{"cmd:nc -U %h", AddressPath},
		{"dgram+cmd:%a", AddressOpaque},
	} {
		x, err := parseExpression(tt.expression)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := x.expand(tt.kind, ""); err == nil {
			t.Fatalf("expanding %q for an empty address = %q, want an error", tt.expression, got)
		}
	}
}

func TestEngineDialsExpressionNetwork(t *testing.T) {
	ctx := context.Background()
	base := Engine{Base: &carrierNet{fakeNet{name: "base"}}}
	tests := []struct {
		engine  Engine
		network string
		address string
		plane   Plane
		calls   []string
	}{
		{base, "test-nc", "127.0.0.1:1", Stream, []string{"base.dial cmd nc 127.0.0.1 1"}},
		{base, "test-nc", "127.0.0.1:0", Stream, []string{"base.dial cmd nc 127.0.0.1 0"}},
		{base, "test-nc", "[fe80::1%p]:80", Stream, []string{"base.dial cmd nc fe80::1%p 80"}},
		{base, "test-nc-unix", "/tmp/a b.sock", Stream, []string{"base.dial cmd nc -U '/tmp/a b.sock'"}},
		{base, "test-nc-udp", "127.0.0.1:1", Packet, []string{"base.dial cmd nc -u -w 30 127.0.0.1 1"}},
		{base, "test-cmd-packet", "nc -u 'a b' 53", Packet, []string{"base.dial cmd nc -u 'a b' 53"}},
		{base, "test-auth-tcp", "[fe80::1%en0]:1", Stream, []string{"test-auth.new", "base.dial tcp fe80::1%en0:1", "test-auth.client"}},
		{base, "test-snappy-unix", "/tmp/a b.sock", Stream, []string{"test-snappy.new", "base.dial unix /tmp/a b.sock", "test-snappy.client"}},
		{base, "test-percent", "127.0.0.1:1", Stream, []string{"base.dial cmd printf %h:%p 127.0.0.1:1"}},
		{base, "test-abs-nc", "127.0.0.1:1", Stream, []string{"base.dial cmd /usr/bin/nc 127.0.0.1 1 #?"}},
		{Engine{}, "test-via-fakenet", "127.0.0.1:1", Stream, []string{"impl.dial fakenet 127.0.0.1:1"}},
	}
	for _, tt := range tests {
		t.Run(tt.network+" "+tt.address, func(t *testing.T) {
			calls = nil
			tr, err := tt.engine.Transport(Chain{Endpoint: Endpoint{Network: tt.network, Address: tt.address}})
			if err != nil {
				t.Fatal(err)
			}
			if tr.Planes() != tt.plane {
				t.Fatalf("Planes() = %v, want %v", tr.Planes(), tt.plane)
			}
			conn, err := tr.Dial(ctx, tt.plane)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := conn.(net.PacketConn); tt.plane == Packet && !ok {
				t.Fatal("Dial(Packet) through dgram returned no net.PacketConn")
			}
			assertCalls(t, tt.calls...)
		})
	}
}

func TestExpressionLayersRefuseALossyHopsDatagrams(t *testing.T) {
	ctx := context.Background()
	tr, err := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}.Transport(chainOver("test-dtls-udp", "127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) of test-dtls over udp the hop reports lossy = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() of test-dtls over udp the hop reports lossy = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
}

func TestExpressionNetworkRefusedByHopWithoutIt(t *testing.T) {
	ctx := context.Background()
	client, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-socks5"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		network string
		plane   Plane
	}{{"test-nc", Stream}, {"test-nc-udp", Packet}} {
		tr, err := Engine{Base: client}.Transport(Chain{Endpoint: Endpoint{Network: tt.network, Address: "127.0.0.1:1"}})
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		if _, err := tr.Dial(ctx, tt.plane); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "dial cmd") {
			t.Fatalf("dialing %s through a client without cmd = %v, want its ErrUnsupported for cmd", tt.network, err)
		}
		assertCalls(t)
	}
}

func TestEngineClosesExpressionLayers(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	tr, err := e.Transport(Chain{Endpoint: Endpoint{Network: "test-closable-tcp", Address: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	closer, ok := tr.(io.Closer)
	if !ok {
		t.Fatal("transport over an expression with a closable layer has no Close")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "closable.close")
	if _, err := e.Transport(Chain{Layers: []Layer{{Scheme: "test-broken"}}, Endpoint: Endpoint{Network: "test-closable-tcp", Address: "127.0.0.1:1"}}); err == nil {
		t.Fatal("build succeeded, want test-broken's failure")
	}
	assertCalls(t, "closable.close")
}

// chainOver is a chain of schemes over network at address.
func chainOver(network, address string, schemes ...string) Chain {
	c := Chain{Endpoint: Endpoint{Network: network, Address: address}}
	for _, s := range schemes {
		c.Layers = append(c.Layers, Layer{Scheme: s})
	}
	return c
}

func TestEngineListensOnExpressionNetwork(t *testing.T) {
	ctx := context.Background()
	base := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		name   string
		engine Engine
		chain  Chain
		calls  []string // what listening on the network's plane calls; nil when it is refused
	}{
		{"at the Listen template", base, chainOver("test-nc", "127.0.0.1:1"), []string{"base.listen cmd nc -l 127.0.0.1 1"}},
		{"at the Listen template for any host", base, chainOver("test-nc", ":8080"), []string{"base.listen cmd nc -l  8080"}},
		{"under the declared name", base, chainOver("test-nc-unix", "/tmp/a b.sock"), []string{"base.listen test-nc-unix /tmp/a b.sock"}},
		{"under the declared name through its implementation", Engine{}, chainOver("test-nc-unix", "/tmp/a b.sock"), []string{"impl.listen test-nc-unix /tmp/a b.sock"}},
		{"under the declared name around dgram", base, chainOver("test-nc-udp", "127.0.0.1:1"), []string{"base.listenpacket test-nc-udp 127.0.0.1:1"}},
		{"under the declared name below the chain's layer", base, chainOver("test-dtls-udp", "127.0.0.1:1", "test-dtls"), []string{"base.listenpacket test-dtls-udp 127.0.0.1:1", "test-dtls.packetconn"}},
		{"refused under a declared name the hop reports lossy", Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"test-dtls-udp"}}}, chainOver("test-dtls-udp", "127.0.0.1:1", "test-dtls"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := tt.engine.Transport(tt.chain)
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			listen := func() error { _, err := tr.Listen(ctx); return err }
			other := func() error { _, err := tr.ListenPacket(ctx); return err }
			if tr.Planes() == Packet {
				listen, other = other, listen
			}
			if err := other(); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("listening off the network's plane = %v, want ErrUnsupported", err)
			}
			assertCalls(t)
			err = listen()
			if tt.calls == nil && !errors.Is(err, ErrUnsupported) || tt.calls != nil && err != nil {
				t.Fatalf("listening = %v, want it to call %q", err, tt.calls)
			}
			assertCalls(t, tt.calls...)
		})
	}
}

func TestListenExpressionSharesTheDialLayers(t *testing.T) {
	ctx := context.Background()
	calls = nil
	tr, err := Engine{Base: &carrierNet{fakeNet{name: "base"}}}.Transport(chainOver("test-auth-tcp", "127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-auth.new")
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.dial tcp 127.0.0.1:1", "test-auth.client", "base.listen tcp 0.0.0.0:1", "test-auth.listener")
}

func TestServerListensUnderTheDeclaredName(t *testing.T) {
	calls = nil
	srv, err := Engine{Base: &fakeNet{name: "base"}}.Server(chainOver("test-nc-unix", "/tmp/a b.sock", "test-socks5"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-socks5.newserver")
	assertRun(t, srv, "base.listen test-nc-unix /tmp/a b.sock", "test-socks5.serve upstream=default")
}
