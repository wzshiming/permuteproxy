package sshproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	"sleep": func(c *command, _ []string) error {
		_, err := io.Copy(io.Discard, c.far)
		return err
	},
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
}

func newUpstream() *upstream {
	return &upstream{commands: make(chan *command, 64)}
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
	near, far := net.Pipe()
	c := &command{Conn: near, far: far, line: address, input: make(chan []byte, 1024), done: make(chan struct{}), killed: make(chan struct{}), closed: make(chan struct{})}
	go func() {
		c.err = programs[argv[0]](c, argv)
		far.Close()
		close(c.done)
	}()
	u.commands <- c
	if argv[0] == "plain" {
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

// clientBase carries test clients to their server, counting dials; it can hold or drop the conns.
type clientBase struct {
	permuteproxy.NetworkFuncs
	dials atomic.Int32
	mu    sync.Mutex
	held  chan struct{} // while set, reads wait for it to close
	conns []net.Conn
}

func (b *clientBase) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.conns = append(b.conns, conn)
	b.mu.Unlock()
	return heldConn{conn, b}, nil
}

// drop closes every conn the base dialed, as a network that went away.
func (b *clientBase) drop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, conn := range b.conns {
		conn.Close()
	}
}

// hold keeps what servers send from the clients until the test ends.
func (b *clientBase) hold(t *testing.T) {
	held := make(chan struct{})
	b.mu.Lock()
	b.held = held
	b.mu.Unlock()
	t.Cleanup(func() { close(held) })
}

func (b *clientBase) wait() {
	b.mu.Lock()
	held := b.held
	b.mu.Unlock()
	if held != nil {
		<-held
	}
}

type heldConn struct {
	net.Conn
	base *clientBase
}

func (c heldConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.base.wait()
	return n, err
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

// rawExecServer hands run each exec's channel, for the stderr this layer's server never sends.
func rawExecServer(t *testing.T, run func(ch ssh.Channel)) string {
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
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					ch, reqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range reqs {
							req.Reply(req.Type == "exec", nil)
							if req.Type == "exec" {
								go run(ch)
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
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

func TestCmdConnectsAgainAfterConnectionDrops(t *testing.T) {
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
	ctx := timeout(t)
	conn, err := n.DialContext(ctx, "cmd", "relay x")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	base.drop()
	// As for tcp, the dial that finds the connection gone fails and the next one connects again.
	if conn, err := n.DialContext(ctx, "cmd", "relay x"); err == nil {
		conn.Close()
		t.Fatal("cmd dial over the dropped connection succeeded")
	}
	conn, err = n.DialContext(ctx, "cmd", "relay x")
	if err != nil {
		t.Fatalf("cmd dial after the connection dropped = %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "relay x|ping")
	if got := base.dials.Load(); got != 2 {
		t.Fatalf("client dials = %d, want one reconnect", got)
	}
}

func TestCmdRefusesLineShlexCannotSplit(t *testing.T) {
	up, base := newUpstream(), &clientBase{}
	n := dialServer(t, base, serveExec(t, up), withCredentials())
	if _, err := n.DialContext(timeout(t), "cmd", "relay 'unterminated"); err == nil || errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("cmd dial = %v, want the line refused", err)
	}
	if base.dials.Load() != 0 || up.dials.Load() != 0 {
		t.Fatalf("client dials %d, server commands %d; want the line refused before any I/O", base.dials.Load(), up.dials.Load())
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

func TestCmdCloseUnblocksReadAtOnce(t *testing.T) {
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
	// Nothing the server sends arrives any more, its answer to the close included.
	base.hold(t)
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	if err := recv(t, closed, "Close to return"); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := recv(t, read, "the pending Read to end"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("pending Read = %v, want net.ErrClosed", err)
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
