package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
	_ "github.com/wzshiming/permuteproxy/protocols/tls"
)

// closeProbe counts dials and the Close calls on connections handed out by the base network.
type closeProbe struct {
	permuteproxy.Network
	dials  atomic.Int32
	closed atomic.Int32
}

func (p *closeProbe) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	p.dials.Add(1)
	conn, err := p.Network.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return testutils.CountingConn{Conn: conn, Closes: &p.closed}, nil
}

func writePEM(t *testing.T, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// issue writes a CA and a leaf certificate for dnsName, returning ca, cert and key file paths.
func issue(t *testing.T, dnsName string) (caFile, certFile, keyFile string) {
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
		DNSNames:     []string{dnsName},
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
	return writePEM(t, "ca.pem", "CERTIFICATE", caDER), writePEM(t, "cert.pem", "CERTIFICATE", leafDER), writePEM(t, "key.pem", "EC PRIVATE KEY", keyDER)
}

func transport(t *testing.T, e permuteproxy.Engine, uri string) permuteproxy.Transport {
	t.Helper()
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := e.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// echoServer serves the TLS listener of a server chain, echoing one message per connection.
func echoServer(t *testing.T, uri string) net.Addr {
	t.Helper()
	ln, err := transport(t, permuteproxy.Engine{}, uri).Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return serveEcho(t, ln)
}

// serveEcho echoes on each connection ln accepts until the test ends.
func serveEcho(t *testing.T, ln net.Listener) net.Addr {
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr()
}

func TestVerifiedHandshake(t *testing.T) {
	caFile, certFile, keyFile := issue(t, "proxy.test")
	addr := echoServer(t, "tls://127.0.0.1:0?tls_cert_file="+certFile+"&tls_key_file="+keyFile)
	base := &closeProbe{Network: testutils.System{}}
	tr := transport(t, permuteproxy.Engine{Base: base}, "tls://"+addr.String()+"?tls_server_name=proxy.test&tls_ca_file="+caFile)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo = %q", got)
	}
	if state := conn.(*tls.Conn).ConnectionState(); state.ServerName != "proxy.test" || len(state.VerifiedChains) == 0 {
		t.Fatalf("handshake not verified for proxy.test: %+v", state)
	}
}

func TestFailedHandshakeClosesSocket(t *testing.T) {
	caFile, certFile, keyFile := issue(t, "proxy.test")
	addr := echoServer(t, "tls://127.0.0.1:0?tls_cert_file="+certFile+"&tls_key_file="+keyFile)
	for name, query := range map[string]string{
		"wrong server name": "?tls_server_name=other.test&tls_ca_file=" + caFile,
		"untrusted issuer":  "?tls_server_name=proxy.test",
	} {
		t.Run(name, func(t *testing.T) {
			base := &closeProbe{Network: testutils.System{}}
			tr := transport(t, permuteproxy.Engine{Base: base}, "tls://"+addr.String()+query)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := tr.Dial(ctx, permuteproxy.Stream)
			if err == nil {
				conn.Close()
				t.Fatal("handshake succeeded")
			}
			var certErr *tls.CertificateVerificationError
			if !errors.As(err, &certErr) {
				t.Fatalf("Dial = %v, want a certificate verification error", err)
			}
			if base.closed.Load() != 1 {
				t.Fatalf("underlying connection closed %d times, want 1", base.closed.Load())
			}
		})
	}
}

func TestServerConfigIsLazy(t *testing.T) {
	listens := 0
	base := permuteproxy.NetworkFuncs{
		DialContextFunc: (&net.Dialer{}).DialContext,
		ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
			listens++
			return (&net.ListenConfig{}).Listen(ctx, network, address)
		},
	}
	tr := transport(t, permuteproxy.Engine{Base: base}, "tls://127.0.0.1:0?tls_skip_verify=true")
	if tr.Planes() != permuteproxy.Stream {
		t.Fatalf("Planes() = %v", tr.Planes())
	}
	_, err := tr.Listen(context.Background())
	if err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("Listen without key material = %v, want a tls config error", err)
	}
	if listens != 0 {
		t.Fatal("inner listener bound before the tls config was ready")
	}
	if _, err := tr.ListenPacket(context.Background()); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("ListenPacket = %v, want ErrUnsupported", err)
	}
}

// install moves an issued certificate and key to the paths a listener reads.
func install(t *testing.T, certFile, keyFile, cert, key string) {
	t.Helper()
	for src, dst := range map[string]string{certFile: cert, keyFile: key} {
		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
	}
}

// verify dials addr through tls, verifying its certificate for name against caFile.
func verify(t *testing.T, addr net.Addr, name, caFile string) error {
	t.Helper()
	tr := transport(t, permuteproxy.Engine{}, "tls://"+addr.String()+"?tls_server_name="+name+"&tls_ca_file="+caFile)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err == nil {
		conn.Close()
	}
	return err
}

func TestFailedServerConfigIsRetried(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	tr := transport(t, permuteproxy.Engine{}, "tls://127.0.0.1:0?tls_cert_file="+cert+"&tls_key_file="+key)
	if _, err := tr.Listen(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Listen before the key material exists = %v, want it missing", err)
	}
	caFile, certFile, keyFile := issue(t, "proxy.test")
	install(t, certFile, keyFile, cert, key)
	ln, err := tr.Listen(context.Background())
	if err != nil {
		t.Fatalf("Listen once the key material exists = %v, want the failed build retried", err)
	}
	if err := verify(t, serveEcho(t, ln), "proxy.test", caFile); err != nil {
		t.Fatalf("handshake after the retried build = %v", err)
	}
}

func TestEachListenBuildsItsServerConfig(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	tr := transport(t, permuteproxy.Engine{}, "tls://127.0.0.1:0?tls_cert_file="+cert+"&tls_key_file="+key)
	for _, name := range []string{"first.test", "second.test"} {
		caFile, certFile, keyFile := issue(t, name)
		install(t, certFile, keyFile, cert, key)
		ln, err := tr.Listen(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(t, serveEcho(t, ln), name, caFile); err != nil {
			t.Fatalf("Listen after installing the %s certificate serves another: %v", name, err)
		}
	}
}

func TestClientConfigIsLazy(t *testing.T) {
	_, certFile, keyFile := issue(t, "proxy.test")
	missing := filepath.Join(t.TempDir(), "missing-ca.pem")
	uri := "tls://127.0.0.1:0?tls_ca_file=" + missing + "&tls_cert_file=" + certFile + "&tls_key_file=" + keyFile
	addr := echoServer(t, uri)
	base := &closeProbe{Network: testutils.System{}}
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	c.Endpoint.Address = addr.String()
	tr, err := permuteproxy.Engine{Base: base}.Transport(c)
	if err != nil {
		t.Fatalf("Transport with an unreadable client CA = %v, want the server side to build", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		conn, err := tr.Dial(ctx, permuteproxy.Stream)
		if err == nil {
			conn.Close()
			t.Fatal("Dial succeeded without its CA file")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Dial = %v, want the missing CA file", err)
		}
	}
	if base.dials.Load() != 0 {
		t.Fatalf("base dialed %d times before the client config was ready", base.dials.Load())
	}
}

func TestCanceledHandshakeClosesSocketOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	base := &closeProbe{Network: testutils.System{}}
	tr := transport(t, permuteproxy.Engine{Base: base}, "tls://"+ln.Addr().String()+"?tls_skip_verify=true")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		conn := <-accepted
		defer conn.Close()
		// The server stays silent; cancel once the ClientHello has arrived.
		conn.Read(make([]byte, 1))
		cancel()
	}()
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err == nil {
		conn.Close()
		t.Fatal("handshake succeeded against a silent server")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want context.Canceled", err)
	}
	if base.closed.Load() != 1 {
		t.Fatalf("underlying connection closed %d times, want 1", base.closed.Load())
	}
}
