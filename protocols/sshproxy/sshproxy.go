package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/shlex"
	"github.com/wzshiming/sshd"
	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"
	"github.com/wzshiming/sshproxy"
	"golang.org/x/crypto/ssh"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"

	keyUDPCommand = "udp_command"
	keyAllowExec  = "allow_exec"

	// maxName bounds a target's host or socket path: no DNS name nor sun_path is longer.
	maxName = 255
)

var options = []string{
	"identity_data",
	"identity_file",
	"authorized_data",
	"authorized_file",
	"hostkey_data",
	"hostkey_file",
	keyUDPCommand,
	keyAllowExec,
}

// endpoint renders the options as the URL form sshproxy parses; the host is a placeholder since
// the inner transport decides where connections go.
func endpoint(opts permuteproxy.Options) string {
	u := url.URL{
		Scheme:   "ssh",
		Host:     "localhost",
		User:     protoutils.Userinfo(opts, KeyUsername, KeyPassword),
		RawQuery: protoutils.Values(opts, KeyUsername, KeyPassword).Encode(),
	}
	return u.String()
}

func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	dialer, err := sshproxy.NewDialer(endpoint(opts))
	if err != nil {
		return nil, err
	}
	udp, ok := opts[keyUDPCommand]
	if !ok {
		udp = cmdutils.NetcatDialUDP
	}
	if _, err := split(udp); err != nil {
		return nil, fmt.Errorf("%s: %w", keyUDPCommand, err)
	}
	c := &client{dialer: dialer}
	return &permuteproxy.ClientFuncs{
		Dial:   c.dial,
		Derive: map[string]string{"udp": "dgram+cmd:" + udp},
		Close:  c.close,
	}, nil
}

// client dials over one SSH connection, made on first use over the stream inner dials.
type client struct {
	dialer *sshproxy.Dialer
	once   sync.Once
	closed atomic.Bool
}

func (c *client) dial(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
	c.once.Do(func() {
		c.dialer.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			// The dialer reconnects whenever it has no connection, so a closed client refuses here.
			if c.closed.Load() {
				return nil, net.ErrClosed
			}
			return inner.Dial(ctx, permuteproxy.Stream)
		}
	})
	if network == "cmd" {
		return c.exec(ctx, address)
	}
	if err := checkName(network, address); err != nil {
		return nil, err
	}
	cli, err := c.dialer.SSHClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := cli.DialContext(ctx, network, address)
	if err != nil && ctx.Err() == nil && dead(err) {
		c.dialer.Close()
	}
	return conn, err
}

// dead reports whether err may come from the connection itself, not a refusal or a bad address.
func dead(err error) bool {
	var refused *ssh.OpenChannelError
	var host *net.AddrError
	var port *strconv.NumError
	return !errors.As(err, &refused) && !errors.As(err, &host) && !errors.As(err, &port)
}

// checkName refuses a target whose host or socket path is too long to be one, before any I/O.
func checkName(network, address string) error {
	name := address
	if network != "unix" {
		name, _, _ = net.SplitHostPort(address)
	}
	if len(name) > maxName {
		return fmt.Errorf("ssh: %s target name of %d bytes is too long", network, len(name))
	}
	return nil
}

func (c *client) close() error {
	c.closed.Store(true)
	return c.dialer.Close()
}

// split splits line into words as a shell would, refusing a line without any.
func split(line string) ([]string, error) {
	argv, err := shlex.Split(line)
	if err == nil && len(argv) == 0 {
		err = fmt.Errorf("%q has no command", line)
	}
	return argv, err
}

// exec runs address, split as a shell would, on a new session of the shared connection.
func (c *client) exec(ctx context.Context, address string) (net.Conn, error) {
	argv, err := split(address)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The SSH handshake, the session's open and the exec's reply ignore ctx, so they run aside.
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	go func() {
		conn, err := c.start(ctx, address, argv)
		select {
		case results <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}()
	select {
	case r := <-results:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// start runs argv on a new session of the shared connection, opening none once ctx has ended.
func (c *client) start(ctx context.Context, address string, argv []string) (net.Conn, error) {
	cli, err := c.dialer.SSHClient(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sess, err := cli.NewSession()
	if err != nil {
		// Drop a dead connection, so that the next dial connects again.
		if dead(err) {
			c.dialer.Close()
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		sess.Close()
		return nil, err
	}
	// The pipes fail only once set or started.
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Start(cmdutils.Quote(argv)); err != nil {
		sess.Close()
		return nil, err
	}
	// A channel's Close only asks the server to close, so reads go through a pipe Close can end here.
	r, w := io.Pipe()
	go func() {
		_, err := io.Copy(w, stdout)
		w.CloseWithError(err)
	}()
	conn := &execConn{sess: sess, stdin: stdin, stdout: r, feed: w, remote: netutils.NewNetAddr("cmd", address), done: make(chan struct{})}
	go func() {
		conn.err = sess.Wait()
		close(conn.done)
	}()
	return conn, nil
}

var (
	localAddr     = netutils.NewNetAddr("cmd", "")
	errNoDeadline = errors.New("ssh: cmd: deadline not supported")
)

// execConn is a remote command's stdin and stdout; its session discards the command's stderr.
type execConn struct {
	sess    *ssh.Session
	writing sync.Mutex // a channel's writes share one packet buffer
	stdin   io.Writer
	stdout  *io.PipeReader
	feed    *io.PipeWriter // what the channel's stdout is copied into
	remote  net.Addr
	done    chan struct{}
	err     error
	closed  atomic.Bool
}

func (c *execConn) Read(b []byte) (int, error) { return c.stdout.Read(b) }

func (c *execConn) Write(b []byte) (int, error) {
	c.writing.Lock()
	defer c.writing.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.stdin.Write(b)
}

func (c *execConn) Close() error {
	c.closed.Store(true)
	c.feed.CloseWithError(net.ErrClosed)
	// Sending the channel's close waits for the transport, which a stalled peer may hold.
	go c.sess.Close()
	return nil
}

func (c *execConn) LocalAddr() net.Addr              { return localAddr }
func (c *execConn) RemoteAddr() net.Addr             { return c.remote }
func (c *execConn) SetDeadline(time.Time) error      { return errNoDeadline }
func (c *execConn) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (c *execConn) SetWriteDeadline(time.Time) error { return errNoDeadline }

// Done closes once the session has ended; Err then holds the exit the server reported.
func (c *execConn) Done() <-chan struct{} { return c.done }
func (c *execConn) Err() error            { return c.err }

// Kill asks the server to kill the command and closes the channel.
func (c *execConn) Kill() error {
	err := c.sess.Signal(ssh.SIGKILL)
	c.sess.Close()
	return err
}

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	allowExec := false
	if value, ok := opts[keyAllowExec]; ok {
		var err error
		if allowExec, err = strconv.ParseBool(value); err != nil {
			return nil, fmt.Errorf("%s: %w", keyAllowExec, err)
		}
	}
	simple, err := sshproxy.NewSimpleServer(endpoint(opts))
	if err != nil {
		return nil, err
	}
	switch {
	case !allowExec:
	case simple.ServerConfig.NoClientAuth:
		return nil, fmt.Errorf("%s without a password or authorized keys", keyAllowExec)
	case simple.ServerConfig.PasswordCallback != nil && simple.Password == "":
		return nil, fmt.Errorf("%s with an empty password", keyAllowExec)
	}
	return &permuteproxy.ServerFuncs{
		Serve: func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
			srv := simple.Server
			srv.Context = ctx
			srv.ProxyDial = upstream.DialContext
			srv.ProxyListen = upstream.Listen
			srv.BytesPool = pool.Bytes
			srv.UserPermissions = func(string) sshd.Permissions { return permissions{exec: allowExec} }
			return srv.Serve(ln)
		},
	}, nil
}

// permissions grant this layer's server users everything but a session, which needs allow_exec.
type permissions struct{ exec bool }

func (p permissions) Allow(req, _ string) bool {
	return req != "session" || p.exec
}

// serveSession runs an exec request's command line as network cmd on the server's upstream.
func serveSession(ctx context.Context, newChan ssh.NewChannel, conn *sshd.ServerConn) {
	// Any sshd server in the process reaches this handler, so only this layer's are served.
	if p, ok := conn.Permissions.(permissions); !ok || !p.Allow("session", "") {
		newChan.Reject(ssh.Prohibited, "exec is not allowed")
		return
	}
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	var cmd net.Conn
	for req := range reqs {
		p, killable := cmd.(netutils.Process)
		switch {
		case req.Type == "exec" && cmd == nil:
			cmd = start(ctx, conn, ch, req)
		case req.Type == "signal" && killable:
			p.Kill()
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
	if cmd != nil {
		cmd.Close()
	}
}

// start dials the command an exec request names, replies whether it runs and pipes it through ch.
func start(ctx context.Context, conn *sshd.ServerConn, ch ssh.Channel, req *ssh.Request) net.Conn {
	var exec sshd.ExecMsg
	if err := ssh.Unmarshal(req.Payload, &exec); err != nil {
		req.Reply(false, nil)
		return nil
	}
	cmd, err := conn.ProxyDial(ctx, "cmd", exec.Command)
	req.Reply(err == nil, nil)
	if err != nil {
		return nil
	}
	go pipe(ch, cmd)
	return cmd
}

// pipe joins ch and cmd until the command's output ends, then reports its exit and closes ch.
func pipe(ch ssh.Channel, cmd net.Conn) {
	go io.Copy(cmd, ch)
	io.Copy(ch, cmd)
	if p, ok := cmd.(netutils.Process); ok {
		<-p.Done()
		if status, ok := exitStatus(p.Err()); ok {
			ch.SendRequest("exit-status", false, ssh.Marshal(sshd.ExitStatusMsg{Status: status}))
		}
	}
	ch.Close()
}

// exitStatus is the status a command's exit error carries, if it carries one.
func exitStatus(err error) (uint32, bool) {
	var coded interface{ ExitCode() int }
	var status interface{ ExitStatus() int } // as *ssh.ExitError reports the status of the next hop
	switch {
	case err == nil:
		return 0, true
	case errors.As(err, &coded) && coded.ExitCode() >= 0:
		return uint32(coded.ExitCode()), true
	case errors.As(err, &status) && status.ExitStatus() >= 0:
		return uint32(status.ExitStatus()), true
	}
	return 0, false
}
