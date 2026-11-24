package netutils

import (
	"net"
	"testing"
)

type fakeProcess struct {
	net.Conn
	done chan struct{}
}

func (p fakeProcess) Done() <-chan struct{} { return p.done }
func (p fakeProcess) Err() error            { return nil }
func (p fakeProcess) Kill() error           { return nil }

func TestWrappersKeepProcess(t *testing.T) {
	local, _ := net.Pipe()
	inner := fakeProcess{Conn: local, done: make(chan struct{})}
	plain, _ := net.Pipe()
	for name, conn := range map[string]net.Conn{
		"closer": ConnWithCloser(inner, local.Close),
		"addr":   ConnWithAddr(inner, nil, nil),
		"nested": ConnWithAddr(ConnWithCloser(inner, local.Close), nil, nil),
		"with":   ConnWithProcess(plain, inner),
	} {
		p, ok := conn.(Process)
		if !ok || p.Done() != inner.done {
			t.Fatalf("%s wrapper lost the process", name)
		}
	}
	if _, ok := ConnWithCloser(plain, plain.Close).(Process); ok {
		t.Fatal("plain conn gained a process")
	}
}
