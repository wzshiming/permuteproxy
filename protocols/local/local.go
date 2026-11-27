package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// Local is the process-local Network: system networking plus cmd, which cmd-packet and the networks of protocols/netcat run on.
type Local struct {
	// Command starts a subprocess whose stdio carries the connection. nil runs it through os/exec:
	// Close returns at once, the command sees EOF on stdin, output it still writes is discarded and
	// it is killed if it is still running WaitDelay later. Only the command itself is waited for;
	// pipes a descendant inherited are closed once it has exited and the connection is closed.
	Command func(ctx context.Context, name string, args ...string) (net.Conn, error)
	// WaitDelay bounds how long a command may keep running after its connection was closed
	// before it is killed, and how long a listener waits for output a command wrote before
	// exiting; zero means 5s, negative values are rejected.
	WaitDelay time.Duration
}

var Network = &Local{}

const defaultWaitDelay = 5 * time.Second

var errNegativeWaitDelay = errors.New("negative WaitDelay")

// command runs name with its stdin fed by the conn's writes and its stdout readable from the conn.
// The conn implements netutils.Process: Done closes once the command has been reaped, Err then
// reports how it ended and Kill terminates it immediately.
func (l *Local) command(ctx context.Context, name string, args ...string) (net.Conn, error) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout = stdinR, stdoutW
	// Cancellation only starts the WaitDelay clock; stdin EOF is the command's cue to leave.
	cmd.Cancel = nil
	cmd.WaitDelay = l.WaitDelay
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = defaultWaitDelay
	}
	err = cmd.Start()
	stdinR.Close()
	stdoutW.Close()
	if err != nil {
		cancel()
		stdinW.Close()
		stdoutR.Close()
		return nil, err
	}
	in, inPeer := net.Pipe()
	out, outPeer := net.Pipe()
	c := &commandConn{in: in, out: out, inPeer: inPeer, stdin: stdinW, stdout: stdoutR, cancel: cancel, process: cmd.Process, done: make(chan struct{})}
	c.holds.Store(2)
	go c.pumpIn(inPeer)
	go c.pumpOut(outPeer)
	go c.wait(cmd)
	return c, nil
}

// commandConn joins two pipes: writes reach the command's stdin through in and its stdout
// arrives through out, so either direction can end without closing the other.
type commandConn struct {
	in, out net.Conn
	inPeer  net.Conn
	stdin   *os.File
	stdout  *os.File
	cancel  context.CancelFunc
	process *os.Process
	once    sync.Once
	holds   atomic.Int32
	done    chan struct{}
	err     error
}

func (c *commandConn) Read(b []byte) (int, error)  { return c.out.Read(b) }
func (c *commandConn) Write(b []byte) (int, error) { return c.in.Write(b) }
func (c *commandConn) LocalAddr() net.Addr         { return c.in.LocalAddr() }
func (c *commandConn) RemoteAddr() net.Addr        { return c.in.RemoteAddr() }

func (c *commandConn) SetDeadline(t time.Time) error {
	c.out.SetReadDeadline(t)
	return c.in.SetWriteDeadline(t)
}

func (c *commandConn) SetReadDeadline(t time.Time) error  { return c.out.SetReadDeadline(t) }
func (c *commandConn) SetWriteDeadline(t time.Time) error { return c.in.SetWriteDeadline(t) }

func (c *commandConn) Close() error {
	c.once.Do(func() {
		c.in.Close()
		c.out.Close()
		c.cancel()
		c.drop()
	})
	return nil
}

func (c *commandConn) Done() <-chan struct{} { return c.done }

func (c *commandConn) Err() error { return c.err }

func (c *commandConn) Kill() error {
	if err := c.process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// drop releases one of the two holds on stdout, the open conn and the live command; the last
// one closes the pipe so a descendant that inherited it cannot keep the pump waiting.
func (c *commandConn) drop() {
	if c.holds.Add(-1) == 0 {
		c.stdout.Close()
	}
}

func (c *commandConn) pumpIn(peer net.Conn) {
	io.Copy(c.stdin, peer)
	c.stdin.Close()
	peer.Close()
}

func (c *commandConn) pumpOut(peer net.Conn) {
	io.Copy(peer, c.stdout)
	// Keep draining after the conn stopped reading so the command can finish and exit.
	io.Copy(io.Discard, c.stdout)
	peer.Close()
}

func (c *commandConn) wait(cmd *exec.Cmd) {
	c.err = cmd.Wait()
	c.stdin.Close()
	c.inPeer.Close()
	c.drop()
	close(c.done)
}

func (l *Local) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "cmd":
		return l.dialCommand(ctx, network, address)
	case "udp", "udp4", "udp6", "unixgram":
		return netutils.DialPacket(ctx, network, address, l.ListenPacket)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	return conn, unsupported(err)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	switch network {
	case "cmd":
		return l.ListenCommand(ctx, address, nil)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
	return ln, unsupported(err)
}

func (l *Local) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	return pc, unsupported(err)
}

// unsupported marks the system's refusal of a network it does not know as ErrUnsupported.
func unsupported(err error) error {
	if errors.As(err, new(net.UnknownNetworkError)) {
		return fmt.Errorf("%w: %w", err, permuteproxy.ErrUnsupported)
	}
	return err
}
