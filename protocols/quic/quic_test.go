package quic_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols/quic"
)

// keys are the options of a listener holding a certificate for proxy.test and of a dialer verifying it.
type keys struct {
	server, client permuteproxy.Options
	caFile         string
}

func writePEM(t *testing.T, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func issue(t *testing.T) keys {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "permuteproxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"proxy.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writePEM(t, "ca.pem", "CERTIFICATE", caDER)
	return keys{
		server: permuteproxy.Options{
			"tls_cert_file": writePEM(t, "cert.pem", "CERTIFICATE", leafDER),
			"tls_key_file":  writePEM(t, "key.pem", "EC PRIVATE KEY", keyDER),
		},
		client: permuteproxy.Options{"tls_server_name": "proxy.test", "tls_ca_file": caFile},
		caFile: caFile,
	}
}

func quicChain(address string, opts permuteproxy.Options) permuteproxy.Chain {
	return permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "quic", Options: opts}}, Endpoint: permuteproxy.Endpoint{Address: address}}
}

func build(t *testing.T, e permuteproxy.Engine, c permuteproxy.Chain) permuteproxy.Transport {
	t.Helper()
	tr, err := e.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// listenQUIC listens through quic on e and returns the listener and the keys to dial it with.
func listenQUIC(t *testing.T, e permuteproxy.Engine) (net.Listener, keys) {
	t.Helper()
	k := issue(t)
	ln, err := build(t, e, quicChain("127.0.0.1:0", k.server)).Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, k
}

// pair listens through quic on e and returns the listener and a transport dialing it.
func pair(t *testing.T, e permuteproxy.Engine) (net.Listener, permuteproxy.Transport) {
	t.Helper()
	ln, k := listenQUIC(t, e)
	return ln, build(t, e, quicChain(ln.Addr().String(), k.client))
}

func dial(t *testing.T, tr permuteproxy.Transport) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// accept hands over the next conn ln accepts; closing ln releases it.
func accept(t *testing.T, ln net.Listener) <-chan net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(ch)
			return
		}
		ch <- c
	}()
	return ch
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v, ok := <-ch:
		if !ok {
			t.Fatalf("%s: channel closed", what)
		}
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: timed out", what)
	}
	panic("unreachable")
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWriteIsSentWithoutMoreData(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	accepted := accept(t, ln)
	c := dial(t, tr)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	srv := recv(t, accepted, "accept")
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(srv, got); err != nil || string(got) != "hello" {
		t.Fatalf("listener read %q, %v; want hello while the dialer waits", got, err)
	}
}

func TestReadEndsAtEOFOnceTheListenerCloses(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	accepted := accept(t, ln)
	c := dial(t, tr)
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	srv := recv(t, accepted, "accept")
	if _, err := io.ReadFull(srv, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(c); err != nil || string(got) != "bye" {
		t.Fatalf("dialer read %q, %v; want bye, then EOF", got, err)
	}
}

func TestReadEndsAtEOFOnceTheDialerCloses(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	accepted := accept(t, ln)
	c := dial(t, tr)
	data := random(t, 256<<10)
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	c.Close()
	srv := recv(t, accepted, "accept")
	srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	if got, err := io.ReadAll(srv); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("listener read %d bytes, %v; want the %d written, then EOF", len(got), err, len(data))
	}
}

func TestAnIdleStreamOutlivesTheIdleTimeout(t *testing.T) {
	quic.SetIdleTimeout(t, 500*time.Millisecond)
	ln, tr := pair(t, permuteproxy.Engine{})
	c, srv := connected(t, ln, tr)
	time.Sleep(1500 * time.Millisecond)
	for _, ends := range [][2]net.Conn{{c, srv}, {srv, c}} {
		if _, err := ends[0].Write([]byte("x")); err != nil {
			t.Fatalf("Write after idling = %v", err)
		}
		ends[1].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(ends[1], make([]byte, 1)); err != nil {
			t.Fatalf("Read after idling = %v", err)
		}
	}
}

func TestListenerMaySpeakFirst(t *testing.T) {
	overCarriers(t, func(t *testing.T, e permuteproxy.Engine) {
		ln, tr := pair(t, e)
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Write([]byte("greeting"))
			}
		}()
		c := dial(t, tr)
		got := make(chan string, 1)
		go func() {
			b := make([]byte, len("greeting"))
			n, _ := io.ReadFull(c, b)
			got <- string(b[:n])
		}()
		if greeting := recv(t, got, "greeting before the dialer writes"); greeting != "greeting" {
			t.Fatalf("dialer read %q, want greeting", greeting)
		}
	})
}

func TestDialBuildsItsTLSConfigBeforeTheCarrier(t *testing.T) {
	base := newRecorder()
	missing := filepath.Join(t.TempDir(), "missing-ca.pem")
	tr := build(t, permuteproxy.Engine{Base: base}, quicChain("127.0.0.1:1", permuteproxy.Options{"tls_ca_file": missing}))
	for range 2 {
		if _, err := tr.Dial(context.Background(), permuteproxy.Stream); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Dial = %v, want the missing CA file", err)
		}
	}
	if len(base.networks) != 0 {
		t.Fatal("carrier bound before the client config was ready")
	}
}

func TestListenBuildsItsTLSConfigBeforeTheBind(t *testing.T) {
	base := newRecorder()
	tr := build(t, permuteproxy.Engine{Base: base}, quicChain("127.0.0.1:0", permuteproxy.Options{"tls_skip_verify": "true"}))
	if _, err := tr.Listen(context.Background()); err == nil {
		t.Fatal("Listen without key material succeeded")
	}
	if len(base.networks) != 0 {
		t.Fatal("carrier bound before the server config was ready")
	}
}

func TestFailedServerConfigIsRetried(t *testing.T) {
	k := issue(t)
	dir := t.TempDir()
	opts := permuteproxy.Options{"tls_cert_file": filepath.Join(dir, "cert.pem"), "tls_key_file": filepath.Join(dir, "key.pem")}
	tr := build(t, permuteproxy.Engine{}, quicChain("127.0.0.1:0", opts))
	if _, err := tr.Listen(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Listen before the key material exists = %v, want it missing", err)
	}
	for key, path := range opts {
		if err := os.Rename(k.server[key], path); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := tr.Listen(context.Background())
	if err != nil {
		t.Fatalf("Listen once the key material exists = %v, want the failed build retried", err)
	}
	defer ln.Close()
	accepted := accept(t, ln)
	c := dial(t, build(t, permuteproxy.Engine{}, quicChain(ln.Addr().String(), k.client)))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, accepted, "accept")
}
