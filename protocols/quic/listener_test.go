package quic_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	xquic "golang.org/x/net/quic"

	"github.com/wzshiming/permuteproxy"
)

// serveEcho echoes each stream ln accepts until its peer closes it.
func serveEcho(ln net.Listener) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
}

// echoed dials tr and checks that n random bytes it writes come back.
func echoed(tr permuteproxy.Transport, n int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	data := make([]byte, n)
	rand.Read(data)
	written := make(chan error, 1)
	go func() {
		_, err := c.Write(data)
		written <- err
	}()
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if err := <-written; err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return errors.New("echo differs from what was written")
	}
	return nil
}

func TestListenerAcceptsStreamsOfEveryConnection(t *testing.T) {
	overCarriers(t, func(t *testing.T, e permuteproxy.Engine) {
		ln, k := listenQUIC(t, e)
		serveEcho(ln)
		const clients, streams = 2, 4
		errs := make(chan error, clients*streams)
		for range clients {
			tr := build(t, e, quicChain(ln.Addr().String(), k.client))
			for range streams {
				go func() { errs <- echoed(tr, 64<<10) }()
			}
		}
		for range clients * streams {
			if err := recv(t, errs, "echo"); err != nil {
				t.Fatal(err)
			}
		}
		if mem, ok := e.Base.(*memNet); ok && mem.loss > 0 {
			if dropped, reordered := mem.impaired(); dropped == 0 || reordered == 0 {
				t.Fatalf("the lossy carrier dropped %d and reordered %d datagrams, want some of each", dropped, reordered)
			}
		}
	})
}

// rawDial connects to addr with x/net/quic itself, offering alpns.
func rawDial(t *testing.T, addr, caFile string, alpns ...string) (*xquic.Conn, error) {
	t.Helper()
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	ep, err := xquic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ep.Close(ctx)
		ep.Close(context.Background())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return ep.Dial(ctx, "udp", addr, &xquic.Config{TLSConfig: &tls.Config{ServerName: "proxy.test", RootCAs: roots, NextProtos: alpns, MinVersion: tls.VersionTLS13}})
}

// rawListen listens with x/net/quic itself on the key material of k, offering the ALPN of permuteproxy.
func rawListen(t *testing.T, k keys) *xquic.Endpoint {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(k.server["tls_cert_file"], k.server["tls_key_file"])
	if err != nil {
		t.Fatal(err)
	}
	ep, err := xquic.Listen("udp", "127.0.0.1:0", &xquic.Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"permuteproxy"}, MinVersion: tls.VersionTLS13}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ep.Close(ctx)
		ep.Close(context.Background())
	})
	return ep
}

func TestListenerAcceptsEveryStreamOfAConnection(t *testing.T) {
	ln, k := listenQUIC(t, permuteproxy.Engine{})
	serveEcho(ln)
	qc, err := rawDial(t, ln.Addr().String(), k.caFile, "permuteproxy")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var streams []*xquic.Stream
	for i := range 3 {
		s, err := qc.NewStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		s.SetReadContext(ctx)
		fmt.Fprintf(s, "stream %d", i)
		s.CloseWrite()
		streams = append(streams, s)
	}
	for i, s := range streams {
		if got, err := io.ReadAll(s); err != nil || string(got) != fmt.Sprintf("stream %d", i) {
			t.Fatalf("stream %d echoed %q, %v", i, got, err)
		}
	}
}

func TestListenerRequiresItsALPN(t *testing.T) {
	ln, k := listenQUIC(t, permuteproxy.Engine{})
	for _, alpns := range [][]string{{"h3"}, nil} {
		// 120 is TLS's no_application_protocol alert.
		if _, err := rawDial(t, ln.Addr().String(), k.caFile, alpns...); err == nil || !strings.Contains(err.Error(), "CRYPTO_ERROR(120)") {
			t.Fatalf("a connection offering %q = %v, want the listener's no_application_protocol alert", alpns, err)
		}
	}
}

func TestListenerCloseAbortsItsConnections(t *testing.T) {
	before := quicGoroutines()
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, srv := connected(t, ln, tr)
	read := make(chan error, 1)
	go func() {
		_, err := srv.Read(make([]byte, 1))
		read <- err
	}()
	accepted := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		accepted <- err
	}()
	time.Sleep(100 * time.Millisecond)
	within(t, 2*time.Second, "Close", func() { ln.Close() })
	released(t, mem.socket(t, 0), "listened")
	if err := recv(t, accepted, "Accept"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept blocked at Close = %v, want net.ErrClosed", err)
	}
	if err := recv(t, read, "accepted Read"); err == nil {
		t.Fatal("Read of an accepted stream outlived its connection")
	}
	setDeadline(t, c.SetReadDeadline, time.Now().Add(5*time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("dialed Read = %v, want the error of the aborted connection", err)
	}
	c.Close()
	noGoroutinesLeft(t, before, time.Second)
}

func TestListenerKeepsNothingOfClientsThatClosed(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{Base: newMemNet()})
	before := quicGoroutines()
	for range 10 {
		c, srv := connected(t, ln, tr)
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(srv, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		c.Close()
		srv.Close()
	}
	noGoroutinesLeft(t, before, 5*time.Second)
}

func TestListenerReportsAFailingCarrier(t *testing.T) {
	before := quicGoroutines()
	mem := newMemNet()
	mem.failRead = errors.New("carrier failed")
	ln, _ := listenQUIC(t, permuteproxy.Engine{Base: mem})
	accepted := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		accepted <- err
	}()
	if err := recv(t, accepted, "Accept over a failing carrier"); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept over a failing carrier = %v, want its failure", err)
	}
	ln.Close()
	released(t, mem.socket(t, 0), "listened")
	noGoroutinesLeft(t, before, time.Second)
}

func TestDialOverAFailingCarrierEndsWithItsContext(t *testing.T) {
	before := quicGoroutines()
	mem := newMemNet()
	mem.failWrite = errors.New("carrier failed")
	tr := build(t, permuteproxy.Engine{Base: mem}, quicChain("127.0.0.1:9", newKeys(t).client))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	within(t, 2*time.Second, "Dial", func() {
		if _, err := tr.Dial(ctx, permuteproxy.Stream); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial over a failing carrier = %v, want its context's deadline", err)
		}
	})
	released(t, mem.socket(t, 0), "dialed")
	noGoroutinesLeft(t, before, time.Second)
}
