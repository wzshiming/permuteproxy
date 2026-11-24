package serverutils

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestListenersListenAfterCloseClosesListener(t *testing.T) {
	fake := &fakeListener{}
	owned := NewListeners(func(context.Context, string, string) (net.Listener, error) { return fake, nil })
	owned.Close()
	if ln, err := owned.Listen(context.Background(), "tcp", "127.0.0.1:0"); ln != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Listen after Close = %v, %v, want nil, net.ErrClosed", ln, err)
	}
	if got := fake.closes.Load(); got != 1 {
		t.Fatalf("listener opened after Close closed %d times, want 1", got)
	}
}
