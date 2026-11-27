package command

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/shlex"

	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var localAddr = netutils.NewNetAddr("cmd", "")

func splitCommand(address string) ([]string, error) {
	args, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	return args, nil
}

func (l *Runner) dial() (cmdutils.DialFunc, error) {
	if l.WaitDelay < 0 {
		return nil, errNegativeWaitDelay
	}
	if l.Command != nil {
		return l.Command, nil
	}
	return l.command, nil
}

// waitDelay is WaitDelay with its zero default applied.
func (l *Runner) waitDelay() time.Duration {
	if l.WaitDelay == 0 {
		return defaultWaitDelay
	}
	return l.WaitDelay
}

func (l *Runner) dialCommand(ctx context.Context, network, address string) (net.Conn, error) {
	args, err := splitCommand(address)
	if err != nil {
		return nil, err
	}
	dial, err := l.dial()
	if err != nil {
		return nil, err
	}
	return cmdutils.DialContext(ctx, dial, localAddr, netutils.NewNetAddr(network, address), args)
}

// CommandFunc starts a command whose stdio is the conn, as Runner.Command does.
type CommandFunc = func(ctx context.Context, name string, args ...string) (net.Conn, error)

// ListenCommand listens as Listen does on cmd at address, a command line run once per connection;
// wrap, when set, is given what starts a command and returns what the listener starts each through.
func (l *Runner) ListenCommand(ctx context.Context, address string, wrap func(start CommandFunc) CommandFunc) (net.Listener, error) {
	args, err := splitCommand(address)
	if err != nil {
		return nil, err
	}
	dial, err := l.dial()
	if err != nil {
		return nil, err
	}
	if wrap != nil {
		dial = cmdutils.DialFunc(wrap(CommandFunc(dial)))
	}
	return cmdutils.Listen(ctx, dial, localAddr, netutils.NewNetAddr("cmd", address), args, l.waitDelay())
}
