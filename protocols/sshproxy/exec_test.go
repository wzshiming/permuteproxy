package sshproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/shlex"
	"github.com/wzshiming/sshd"
	"golang.org/x/crypto/ssh"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// exitCode is the error a fake command exits with to report a status.
type exitCode int

func (e exitCode) Error() string { return "exit status " + strconv.Itoa(int(e)) }
func (e exitCode) ExitCode() int { return int(e) }

// command is a process of the fake upstream: the server holds its conn, its program the far end.
type command struct {
	net.Conn
	far    net.Conn
	line   string
	input  chan []byte // what the record program reads
	done   chan struct{}
	err    error
	killed chan struct{}
	closed chan struct{}
	kill   sync.Once
	close  sync.Once
}

func (c *command) Done() <-chan struct{} { return c.done }
func (c *command) Err() error            { return c.err }

func (c *command) Kill() error {
	c.kill.Do(func() { close(c.killed) })
	return c.far.Close()
}

func (c *command) Close() error {
	c.close.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// programs run on the far end of a command's conn, picked by the first word of its line.
var programs = map[string]func(c *command, argv []string) error{
	"relay": relay,
	"nc":    relay,
	"socat": relay,
	"exit": func(c *command, argv []string) error {
		c.far.Write([]byte("bye"))
		if code, _ := strconv.Atoi(argv[1]); code != 0 {
			return exitCode(code)
		}
		return nil
	},
	"fail": func(c *command, _ []string) error {
		c.far.Write([]byte("bye"))
		return errors.New("no status")
	},
	"plain": func(c *command, _ []string) error {
		c.far.Write([]byte("bye"))
		return nil
	},
	"sleep":  drain,
	"linger": drain,
	"stall":  drain, // its exec request waits for the reply until upstream.released closes
	"record": func(c *command, _ []string) error {
		for {
			buf := make([]byte, 64<<10)
			n, err := c.far.Read(buf)
			if err != nil {
				return nil
			}
			c.input <- buf[:n]
		}
	},
}

// drain reads what it is sent until its input ends.
func drain(c *command, _ []string) error {
	_, err := io.Copy(io.Discard, c.far)
	return err
}

// relay answers each read with its line and what it read, the way a datagram relay names its peer.
func relay(c *command, _ []string) error {
	buf := make([]byte, 1024)
	for {
		n, err := c.far.Read(buf)
		if err != nil {
			return nil
		}
		if _, err := fmt.Fprintf(c.far, "%s|%s", c.line, buf[:n]); err != nil {
			return nil
		}
	}
}

// upstream is the servers' fake Upstream: tcp reaches the system, cmd runs a program in process.
type upstream struct {
	permuteproxy.NetworkFuncs
	dials    atomic.Int32
	commands chan *command
	stalls   chan string // the line of each stall command whose exec request arrived
	released chan struct{}
}

func newUpstream() *upstream {
	return &upstream{commands: make(chan *command, 64), stalls: make(chan string, 64), released: make(chan struct{})}
}

func (u *upstream) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "cmd" {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	u.dials.Add(1)
	argv, err := shlex.Split(address)
	if err != nil || len(argv) == 0 || programs[argv[0]] == nil {
		return nil, fmt.Errorf("no program runs %q", address)
	}
	if argv[0] == "stall" {
		u.stalls <- address
		select {
		case <-u.released:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	near, far := net.Pipe()
	c := &command{Conn: near, far: far, line: address, input: make(chan []byte, 1024), done: make(chan struct{}), killed: make(chan struct{}), closed: make(chan struct{})}
	go func() {
		c.err = programs[argv[0]](c, argv)
		far.Close()
		close(c.done)
	}()
	u.commands <- c
	if argv[0] == "plain" || argv[0] == "linger" {
		// A conn that is not a netutils.Process, whose exit nobody can tell.
		return struct{ net.Conn }{c}, nil
	}
	return c, nil
}

// chain is this layer with opts over tcp at address.
func chain(opts permuteproxy.Options, address string) permuteproxy.Chain {
	return permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "ssh", Options: opts}}, Endpoint: permuteproxy.Endpoint{Network: "tcp", Address: address}}
}

// withCredentials is the username and password every test server and client shares, plus pairs kv.
func withCredentials(kv ...string) permuteproxy.Options {
	opts := permuteproxy.Options{"username": "u", "password": "p"}
	for i := 0; i+1 < len(kv); i += 2 {
		opts[kv[i]] = kv[i+1]
	}
	return opts
}

// serve runs this layer's server with opts through the Engine on loopback and returns its address.
func serve(t *testing.T, opts permuteproxy.Options, up permuteproxy.Network) string {
	t.Helper()
	bound := make(chan string, 1)
	base := permuteproxy.NetworkFuncs{ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err == nil {
			bound <- ln.Addr().String()
		}
		return ln, err
	}}
	srv, err := permuteproxy.Engine{Base: base, Upstream: up}.Server(chain(opts, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after Close")
		}
	})
	select {
	case addr := <-bound:
		return addr
	case err := <-done:
		t.Fatalf("server exited before binding: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not bind")
	}
	return ""
}

// serveExec serves exec with authentication set, running commands through up.
func serveExec(t *testing.T, up permuteproxy.Network) string {
	t.Helper()
	return serve(t, withCredentials("allow_exec", "true", "hostkey_data", hostKey), up)
}

// clientBase carries test clients to their server, counting dials; it holds, stalls or drops conns.
type clientBase struct {
	permuteproxy.NetworkFuncs
	dials   atomic.Int32
	mu      sync.Mutex
	held    chan struct{} // while set, reads wait for it to close
	stalled chan struct{} // while set, writes wait for it to close
	conns   []*baseConn
}

func (b *clientBase) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	c := &baseConn{Conn: conn, base: b, closed: make(chan struct{})}
	b.mu.Lock()
	b.conns = append(b.conns, c)
	b.mu.Unlock()
	return c, nil
}

// drop closes every conn the base dialed, as a network that went away.
func (b *clientBase) drop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		c.Conn.Close()
	}
}

// mute has the conns dialed so far swallow what they send, as on a silent link, and returns them.
func (b *clientBase) mute() []*baseConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		c.muted.Store(true)
	}
	return slices.Clone(b.conns)
}

// freeze fails the writes of the conns dialed so far and defers their Close to thaw.
func (b *clientBase) freeze() (thaw func()) {
	b.mu.Lock()
	conns := slices.Clone(b.conns)
	b.mu.Unlock()
	for _, c := range conns {
		c.frozen.Store(true)
	}
	return func() {
		for _, c := range conns {
			c.Conn.Close()
		}
	}
}

// hold keeps what servers send from the clients until the test ends.
func (b *clientBase) hold(t *testing.T) { b.block(t, &b.held) }

// stall keeps what the clients send from the servers until the test ends.
func (b *clientBase) stall(t *testing.T) { b.block(t, &b.stalled) }

// block sets gate to a chan the end of the test closes.
func (b *clientBase) block(t *testing.T, gate *chan struct{}) {
	blocked := make(chan struct{})
	b.mu.Lock()
	*gate = blocked
	b.mu.Unlock()
	t.Cleanup(func() { close(blocked) })
}

// wait returns once gate is unset or closed.
func (b *clientBase) wait(gate *chan struct{}) {
	b.mu.Lock()
	blocked := *gate
	b.mu.Unlock()
	if blocked != nil {
		<-blocked
	}
}

// baseConn is a conn of clientBase; muted, its writes vanish; frozen, they fail and Close keeps it.
type baseConn struct {
	net.Conn
	base   *clientBase
	muted  atomic.Bool
	frozen atomic.Bool
	closed chan struct{} // closes with the first Close
	close  sync.Once
}

func (c *baseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.base.wait(&c.base.held)
	return n, err
}

func (c *baseConn) Write(p []byte) (int, error) {
	c.base.wait(&c.base.stalled)
	switch {
	case c.frozen.Load():
		return 0, io.ErrClosedPipe
	case c.muted.Load():
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *baseConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	if c.frozen.Load() {
		return nil
	}
	return c.Conn.Close()
}

// dialServer builds this layer's client with opts of the server at addr through the Engine.
func dialServer(t *testing.T, base permuteproxy.Network, addr string, opts permuteproxy.Options) permuteproxy.Network {
	t.Helper()
	n, err := permuteproxy.Engine{Base: base}.Client(chain(opts, addr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.(io.Closer).Close() })
	return n
}

func timeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// process is conn's netutils.Process, failing the test when it has none.
func process(t *testing.T, conn net.Conn) netutils.Process {
	t.Helper()
	p, ok := conn.(netutils.Process)
	if !ok {
		t.Fatalf("%T is not a netutils.Process", conn)
	}
	return p
}

// readAll reads conn to its end aside, since ssh conns refuse deadlines.
func readAll(t *testing.T, conn net.Conn) string {
	t.Helper()
	read := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(conn)
		read <- out
	}()
	return string(recv(t, read, "the output to end"))
}

// dialAside dials n aside, closing the conn if any, and reports the dial's error.
func dialAside(ctx context.Context, n permuteproxy.Network, network, address string) <-chan error {
	dialed := make(chan error, 1)
	go func() {
		conn, err := n.DialContext(ctx, network, address)
		if conn != nil {
			conn.Close()
		}
		dialed <- err
	}()
	return dialed
}

// rawServer serves SSH on loopback without authentication, handing on new channels and requests.
func rawServer(t *testing.T, handle func(newChan ssh.NewChannel), answer func(reqs <-chan *ssh.Request)) string {
	t.Helper()
	signer, err := ssh.ParsePrivateKey(hostKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go answer(reqs)
				for newChan := range chans {
					handle(newChan)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// rawExecServer hands run each exec's channel, for the stderr this layer's server never sends.
func rawExecServer(t *testing.T, run func(ch ssh.Channel)) string {
	t.Helper()
	return rawServer(t, func(newChan ssh.NewChannel) {
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range reqs {
				req.Reply(req.Type == "exec", nil)
				if req.Type == "exec" {
					go run(ch)
				}
			}
		}()
	}, ssh.DiscardRequests)
}

func TestCmdRoundTripsThroughExec(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	conn, err := n.DialContext(timeout(t), "cmd", `relay "a b" c`)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The line is split as a shell would and quoted back for the server.
	if got, want := recv(t, up.commands, "the command").line, "relay 'a b' c"; got != want {
		t.Fatalf("server ran %q, want %q", got, want)
	}
	roundTrip(t, conn, "ping", "relay 'a b' c|ping")
}

func TestCmdFailsWhenServerCannotRunIt(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	if conn, err := n.DialContext(timeout(t), "cmd", "bogus"); err == nil {
		conn.Close()
		t.Fatal("cmd dial of a command the server cannot run succeeded")
	}
	conn, err := n.DialContext(timeout(t), "cmd", "relay x")
	if err != nil {
		t.Fatalf("cmd dial after a refused one = %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "relay x|ping")
}

func TestDialConnectsAgainAfterConnectionDrops(t *testing.T) {
	target := echoTarget(t)
	for _, tt := range []struct{ network, address, reply string }{
		{"cmd", "relay x", "relay x|ping"},
		{"tcp", target, "ping"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			base := &clientBase{}
			n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
			ctx := timeout(t)
			conn, err := n.DialContext(ctx, tt.network, tt.address)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			base.drop()
			// The dial that finds the connection gone fails and the next one connects again.
			if conn, err := n.DialContext(ctx, tt.network, tt.address); err == nil {
				conn.Close()
				t.Fatal("dial over the dropped connection succeeded")
			}
			conn, err = n.DialContext(ctx, tt.network, tt.address)
			if err != nil {
				t.Fatalf("dial after the connection dropped = %v", err)
			}
			defer conn.Close()
			roundTrip(t, conn, "ping", tt.reply)
			if got := base.dials.Load(); got != 2 {
				t.Fatalf("client dials = %d, want one reconnect", got)
			}
		})
	}
}

func TestCmdRefusesLineWithoutCommand(t *testing.T) {
	up, base := newUpstream(), &clientBase{}
	n := dialServer(t, base, serveExec(t, up), withCredentials())
	for _, line := range []string{"relay 'unterminated", "", " ", "# only a comment"} {
		if conn, err := n.DialContext(timeout(t), "cmd", line); err == nil || errors.Is(err, permuteproxy.ErrUnsupported) {
			if conn != nil {
				conn.Close()
			}
			t.Errorf("cmd dial %q = %v, want the line refused", line, err)
		}
	}
	if base.dials.Load() != 0 || up.dials.Load() != 0 {
		t.Fatalf("client dials %d, server commands %d; want the lines refused before any I/O", base.dials.Load(), up.dials.Load())
	}
}

func TestCmdDialWithCanceledCtxStartsNothing(t *testing.T) {
	up, base := newUpstream(), &clientBase{}
	n := dialServer(t, base, serveExec(t, up), withCredentials())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	// The dial path runs aside, so the counts are read after it would have reached the Base.
	dial := func() error {
		conn, err := n.DialContext(canceled, "cmd", "relay x")
		if conn != nil {
			conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
		return err
	}
	if err := dial(); !errors.Is(err, context.Canceled) || base.dials.Load() != 0 {
		t.Fatalf("cmd dial before connecting = %v after %d client dials, want context.Canceled and none", err, base.dials.Load())
	}
	conn, err := n.DialContext(timeout(t), "cmd", "relay x")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := dial(); !errors.Is(err, context.Canceled) || up.dials.Load() != 1 {
		t.Fatalf("cmd dial once connected = %v after %d server commands, want context.Canceled and only the first", err, up.dials.Load())
	}
}

func TestCmdDialEndingWhileConnectingOpensNoSession(t *testing.T) {
	opened := make(chan struct{}, 8)
	addr := rawServer(t, func(newChan ssh.NewChannel) {
		opened <- struct{}{}
		newChan.Reject(ssh.Prohibited, "counted only")
	}, ssh.DiscardRequests)
	connecting, connect := make(chan struct{}, 1), make(chan struct{})
	base := permuteproxy.NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
		connecting <- struct{}{}
		<-connect
		return net.Dial(network, address)
	}}
	n := dialServer(t, base, addr, nil)
	release := sync.OnceFunc(func() { close(connect) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	dialed := dialAside(ctx, n, "cmd", "anything")
	recv(t, connecting, "the dial to connect")
	cancel()
	if err := recv(t, dialed, "the dial to end with its ctx"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cmd dial = %v, want context.Canceled", err)
	}
	// The connection made after the dial gave up carries the next dial's session only.
	release()
	var refused *ssh.OpenChannelError
	if _, err := n.DialContext(timeout(t), "cmd", "anything"); !errors.As(err, &refused) {
		t.Fatalf("next cmd dial = %v, want its session refused", err)
	}
	recv(t, opened, "the next dial's session")
	select {
	case <-opened:
		t.Fatal("the dial that gave up while connecting opened a session")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestCmdDialEndsWithCtxWhileSessionOpens(t *testing.T) {
	opened, accept, ended := make(chan struct{}, 1), make(chan struct{}), make(chan int, 1)
	release := sync.OnceFunc(func() { close(accept) })
	addr := rawServer(t, func(newChan ssh.NewChannel) {
		opened <- struct{}{}
		go func() {
			<-accept
			ch, reqs, err := newChan.Accept()
			if err != nil {
				return
			}
			execs := 0
			for req := range reqs {
				if req.Type == "exec" {
					execs++
				}
				req.Reply(false, nil)
			}
			ch.Close()
			ended <- execs
		}()
	}, ssh.DiscardRequests)
	n := dialServer(t, &clientBase{}, addr, nil)
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := dialAside(ctx, n, "cmd", "anything")
	recv(t, opened, "the session's channel to be opened")
	cancel()
	if err := recv(t, dialed, "the dial to end with its ctx"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cmd dial = %v, want context.Canceled", err)
	}
	// The session the server opens too late is closed before any command starts.
	release()
	if execs := recv(t, ended, "the late session to close"); execs != 0 {
		t.Fatalf("late session got %d exec requests, want none", execs)
	}
}

func TestCmdDialEndsWithCtxWhileExecWaits(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := dialAside(ctx, n, "cmd", "stall")
	recv(t, up.stalls, "the exec request")
	cancel()
	if err := recv(t, dialed, "the dial to end with its ctx"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cmd dial = %v, want context.Canceled", err)
	}
	// The command the server starts too late has its session closed, which ends it.
	close(up.released)
	cmd := recv(t, up.commands, "the late command")
	recv(t, cmd.closed, "the late command to close")
}

func TestAbandonedCmdDialFailingLateKeepsTheNextConnection(t *testing.T) {
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
	target := echoTarget(t)
	warm, err := n.DialContext(timeout(t), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	warm.Close()
	base.mute()
	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if conn, err := n.DialContext(short, "cmd", "relay x"); !errors.Is(err, context.DeadlineExceeded) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("cmd dial over the silent connection = %v, want context.DeadlineExceeded", err)
	}
	// The client gives up the old connection, which ends only once thawed.
	thaw := base.freeze()
	for try := 0; base.dials.Load() < 2; try++ {
		if try == 10 {
			t.Fatal("the client did not connect again")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if conn, err := n.DialContext(ctx, "tcp", target); err == nil {
			conn.Close()
		}
		cancel()
	}
	conn, err := n.DialContext(timeout(t), "cmd", "relay x")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Its end fails the abandoned dial's session open now.
	thaw()
	select {
	case <-process(t, conn).Done():
		t.Fatal("a cmd conn of the new connection ended with the old one")
	case <-time.After(300 * time.Millisecond):
	}
	roundTrip(t, conn, "ping", "relay x|ping")
	if got := base.dials.Load(); got != 2 {
		t.Fatalf("client dials = %d, want one reconnect", got)
	}
}

func TestClosingCmdClosesServerCommand(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	conn, err := n.DialContext(timeout(t), "cmd", "sleep")
	if err != nil {
		t.Fatal(err)
	}
	cmd := recv(t, up.commands, "the command")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	recv(t, cmd.closed, "the server to close the command")
}

func TestCmdCloseReturnsAndUnblocksReadAtOnce(t *testing.T) {
	for name, block := range map[string]func(*clientBase, *testing.T){
		// Nothing the server sends arrives any more, its answer to the close included.
		"reads held": (*clientBase).hold,
		// Nothing reaches the server any more, the close itself included.
		"writes stalled": (*clientBase).stall,
	} {
		t.Run(name, func(t *testing.T) {
			base := &clientBase{}
			n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
			conn, err := n.DialContext(timeout(t), "cmd", "sleep")
			if err != nil {
				t.Fatal(err)
			}
			read := make(chan error, 1)
			go func() {
				_, err := conn.Read(make([]byte, 1))
				read <- err
			}()
			block(base, t)
			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			if err := recv(t, closed, "Close to return"); err != nil {
				t.Fatalf("Close = %v", err)
			}
			if err := recv(t, read, "the pending Read to end"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("pending Read = %v, want net.ErrClosed", err)
			}
		})
	}
}

func TestCmdWriteAfterCloseReturnsErrClosed(t *testing.T) {
	n := dialServer(t, &clientBase{}, serveExec(t, newUpstream()), withCredentials())
	conn, err := n.DialContext(timeout(t), "cmd", "sleep")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, err := conn.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}
}

func TestCmdReportsExitStatus(t *testing.T) {
	n := dialServer(t, &clientBase{}, serveExec(t, newUpstream()), withCredentials())
	for _, tt := range []struct {
		line   string
		status int // -1 for none reported
	}{
		{"exit 0", 0},
		{"exit 3", 3},
		{"exit -1", -1},
		{"fail", -1},
		{"plain", -1},
	} {
		t.Run(tt.line, func(t *testing.T) {
			conn, err := n.DialContext(timeout(t), "cmd", tt.line)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if out := readAll(t, conn); out != "bye" {
				t.Fatalf("output = %q, want bye", out)
			}
			p := process(t, conn)
			recv(t, p.Done(), "the command to exit")
			var exit *ssh.ExitError
			var missing *ssh.ExitMissingError
			switch err := p.Err(); {
			case tt.status == 0 && err == nil:
			case tt.status > 0 && errors.As(err, &exit) && exit.ExitStatus() == tt.status:
			case tt.status < 0 && errors.As(err, &missing):
			default:
				t.Fatalf("Err() = %v, want status %d", err, tt.status)
			}
		})
	}
}

func TestCmdExitStatusSurvivesTwoHops(t *testing.T) {
	first := dialServer(t, &clientBase{}, serveExec(t, newUpstream()), withCredentials())
	n := dialServer(t, &clientBase{}, serveExec(t, first), withCredentials())
	conn, err := n.DialContext(timeout(t), "cmd", "exit 3")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if out := readAll(t, conn); out != "bye" {
		t.Fatalf("output = %q, want bye", out)
	}
	p := process(t, conn)
	recv(t, p.Done(), "the command to exit")
	var exit *ssh.ExitError
	if err := p.Err(); !errors.As(err, &exit) || exit.ExitStatus() != 3 {
		t.Fatalf("Err() through two hops = %v, want status 3", err)
	}
}

func TestCmdKillEndsFarCommand(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	conn, err := n.DialContext(timeout(t), "cmd", "sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cmd := recv(t, up.commands, "the command")
	p := process(t, conn)
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	recv(t, cmd.killed, "the server to kill the command")
	recv(t, cmd.done, "the killed command to end")
	recv(t, p.Done(), "the client to see the command end")
}

func TestCmdKillClosesTheSession(t *testing.T) {
	up := newUpstream()
	n := dialServer(t, &clientBase{}, serveExec(t, up), withCredentials())
	conn, err := n.DialContext(timeout(t), "cmd", "linger")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cmd := recv(t, up.commands, "the command")
	if err := process(t, conn).Kill(); err != nil {
		t.Fatal(err)
	}
	// The server cannot signal a conn without a process, so only the session's close ends it.
	recv(t, cmd.closed, "the server to close the command")
}

func TestCmdDiscardsRemoteStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = stderr }()
	addr := rawExecServer(t, func(ch ssh.Channel) {
		ch.Stderr().Write([]byte("leak"))
		ch.Write([]byte("out"))
		ch.SendRequest("exit-status", false, ssh.Marshal(sshd.ExitStatusMsg{}))
		ch.Close()
	})
	n := dialServer(t, &clientBase{}, addr, nil)
	conn, err := n.DialContext(timeout(t), "cmd", "anything")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if out := readAll(t, conn); out != "out" {
		t.Fatalf("output = %q, want out", out)
	}
	// Done follows the session's own stderr copy, so whatever it wrote is written by now.
	recv(t, process(t, conn).Done(), "the command to exit")
	os.Stderr = stderr
	w.Close()
	if leaked, _ := io.ReadAll(r); len(leaked) != 0 {
		t.Fatalf("this process's stderr got %q", leaked)
	}
}

func TestExecSessionServesOneExecOnly(t *testing.T) {
	up := newUpstream()
	cli, err := ssh.Dial("tcp", serveExec(t, up), &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.Password("p")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	for name, accepted := range map[string]func(*ssh.Session) bool{
		"shell":          func(s *ssh.Session) bool { return s.Shell() == nil },
		"pty-req":        func(s *ssh.Session) bool { return s.RequestPty("xterm", 24, 80, nil) == nil },
		"env":            func(s *ssh.Session) bool { return s.Setenv("A", "b") == nil },
		"subsystem":      func(s *ssh.Session) bool { return s.RequestSubsystem("sftp") == nil },
		"malformed exec": func(s *ssh.Session) bool { ok, _ := s.SendRequest("exec", true, []byte{0}); return ok },
		"signal before exec": func(s *ssh.Session) bool {
			ok, _ := s.SendRequest("signal", true, ssh.Marshal(struct{ Signal string }{"TERM"}))
			return ok
		},
	} {
		sess, err := cli.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if accepted(sess) {
			t.Errorf("%s request accepted", name)
		}
		sess.Close()
	}
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start("sleep"); err != nil {
		t.Fatalf("exec request = %v", err)
	}
	cmd := recv(t, up.commands, "the command")
	if ok, err := sess.SendRequest("exec", true, ssh.Marshal(sshd.ExecMsg{Command: "sleep"})); ok || err != nil {
		t.Fatalf("second exec = %v, %v; want it refused", ok, err)
	}
	if got := up.dials.Load(); got != 1 {
		t.Fatalf("server commands = %d, want only the first exec's", got)
	}
	if ok, err := sess.SendRequest("signal", true, ssh.Marshal(struct{ Signal string }{"TERM"})); !ok || err != nil {
		t.Fatalf("signal = %v, %v; want it accepted", ok, err)
	}
	recv(t, cmd.killed, "the signal to kill the command")
}

func TestExecOffRefusesSessionsAndKeepsTcp(t *testing.T) {
	for name, opts := range map[string]permuteproxy.Options{
		"absent": withCredentials("hostkey_data", hostKey),
		"false":  withCredentials("hostkey_data", hostKey, "allow_exec", "false"),
	} {
		t.Run(name, func(t *testing.T) {
			up, base := newUpstream(), &clientBase{}
			n := dialServer(t, base, serve(t, opts, up), withCredentials())
			ctx := timeout(t)
			_, err := n.DialContext(ctx, "cmd", "relay x")
			var refused *ssh.OpenChannelError
			if !errors.As(err, &refused) || refused.Reason != ssh.Prohibited {
				t.Fatalf("cmd dial = %v, want the session refused as prohibited", err)
			}
			// A udp dial opens its session on the first write.
			udp, err := n.DialContext(ctx, "udp", "198.51.100.7:53")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			if _, err := udp.Write([]byte("hi")); !errors.As(err, &refused) || refused.Reason != ssh.Prohibited {
				t.Fatalf("udp write = %v, want the session refused as prohibited", err)
			}
			conn, err := n.DialContext(ctx, "tcp", echoTarget(t))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			roundTrip(t, conn, "ping", "ping")
			if up.dials.Load() != 0 || base.dials.Load() != 1 {
				t.Fatalf("server commands %d, client dials %d; want none run and the connection kept", up.dials.Load(), base.dials.Load())
			}
		})
	}
}

// authorizedKey is the public half of hostKeyPEM as the authorized_data option carries it.
var authorizedKey = func() string {
	signer, err := ssh.ParsePrivateKey(hostKeyPEM)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}()

func TestServerBuildRefusesUnguardedOrMalformedExec(t *testing.T) {
	for name, opts := range map[string]permuteproxy.Options{
		"no credentials":             {"allow_exec": "true", "hostkey_data": hostKey},
		"username alone":             {"allow_exec": "true", "hostkey_data": hostKey, "username": "u"},
		"empty password":             {"allow_exec": "true", "hostkey_data": hostKey, "username": "u", "password": ""},
		"empty password beside keys": {"allow_exec": "true", "hostkey_data": hostKey, "username": "u", "password": "", "authorized_data": authorizedKey},
		"malformed":                  withCredentials("allow_exec", "maybe", "hostkey_data", hostKey),
	} {
		t.Run(name, func(t *testing.T) {
			base := &countingNetwork{}
			if _, err := (permuteproxy.Engine{Base: base, Upstream: base}).Server(chain(opts, "127.0.0.1:0")); !errors.Is(err, permuteproxy.ErrInvalidChain) {
				t.Fatalf("Server() = %v, want ErrInvalidChain", err)
			}
			if got := base.calls.Load(); got != 0 {
				t.Fatalf("network calls = %d, want none", got)
			}
		})
	}
	for name, opts := range map[string]permuteproxy.Options{
		"password":        withCredentials("allow_exec", "true", "hostkey_data", hostKey),
		"authorized keys": {"allow_exec": "true", "hostkey_data": hostKey, "authorized_data": authorizedKey},
	} {
		t.Run(name, func(t *testing.T) {
			srv, err := permuteproxy.Engine{Base: &countingNetwork{}}.Server(chain(opts, "127.0.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			srv.Close()
		})
	}
}

func TestSessionsOfOtherSSHDServersStayRefused(t *testing.T) {
	up := newUpstream()
	signer, err := ssh.ParsePrivateKey(hostKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := &sshd.Server{ProxyDial: up.DialContext}
	srv.ServerConfig.NoClientAuth = true
	srv.ServerConfig.AddHostKey(signer)
	ln := listen(t)
	go srv.Serve(ln)
	n := dialServer(t, &clientBase{}, ln.Addr().String(), nil)
	_, err = n.DialContext(timeout(t), "cmd", "relay x")
	var refused *ssh.OpenChannelError
	if !errors.As(err, &refused) {
		t.Fatalf("cmd dial = %v, want the session refused", err)
	}
	if got := up.dials.Load(); got != 0 {
		t.Fatalf("server commands = %d, want none", got)
	}
}
