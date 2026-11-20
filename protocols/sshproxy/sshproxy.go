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
	c := &client{dialer: dialer}
	return &permuteproxy.ClientFuncs{
		Dial:   c.dial,
		Derive: map[string]string{"udp": "dgram+cmd:" + udp},
		Close:  dialer.Close,
	}, nil
}

// client dials over one SSH connection, made on first use over the stream inner dials.
type client struct {
	dialer *sshproxy.Dialer
	once   sync.Once
}

func (c *client) dial(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
	c.once.Do(func() {
		c.dialer.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return inner.Dial(ctx, permuteproxy.Stream)
		}
	})
	if network == "cmd" {
		return c.exec(ctx, address)
	}
	return c.dialer.DialContext(ctx, network, address)
}

// exec runs address, split as a shell would, on a new session of the shared connection.
func (c *client) exec(ctx context.Context, address string) (net.Conn, error) {
	argv, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	cli, err := c.dialer.SSHClient(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := cli.NewSession()
	if err != nil {
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
	sess   *ssh.Session
	stdin  io.Writer
	stdout *io.PipeReader
	feed   *io.PipeWriter // what the channel's stdout is copied into
	remote net.Addr
	done   chan struct{}
	err    error
}

func (c *execConn) Read(b []byte) (int, error)  { return c.stdout.Read(b) }
func (c *execConn) Write(b []byte) (int, error) { return c.stdin.Write(b) }

func (c *execConn) Close() error {
	c.feed.CloseWithError(net.ErrClosed)
	return c.sess.Close()
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
	if allowExec && simple.ServerConfig.NoClientAuth {
		return nil, fmt.Errorf("%s without a password or authorized keys", keyAllowExec)
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

// permissions grant the users of this layer's servers everything but a session, which needs allow_exec.
type permissions struct{ exec bool }

func (p permissions) Allow(req, _ string) bool {
	return req != "session" || p.exec
}

// serveSession runs the command line of an exec request as network cmd through the server's upstream.
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

// pipe copies both ways between ch and cmd until the command's output ends, then reports its exit and closes ch.
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
	switch {
	case err == nil:
		return 0, true
	case errors.As(err, &coded) && coded.ExitCode() >= 0:
		return uint32(coded.ExitCode()), true
	}
	return 0, false
}
