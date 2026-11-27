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

func TestListenersForgetAClosedListener(t *testing.T) {
	fake := &fakeListener{}
	owned := NewListeners(func(context.Context, string, string) (net.Listener, error) { return fake, nil })
	ln, err := owned.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	ln.Close()
	if got := len(owned.lns); got != 0 {
		t.Fatalf("Listeners holds %d listeners after the only one closed, want 0", got)
	}
	owned.Close()
	if got := fake.closes.Load(); got != 1 {
		t.Fatalf("listener closed %d times, want 1", got)
	}
}

func TestListenersCloseClosesOpenListeners(t *testing.T) {
	fakes := []*fakeListener{{}, {}}
	next := 0
	owned := NewListeners(func(context.Context, string, string) (net.Listener, error) {
		next++
		return fakes[next-1], nil
	})
	for range fakes {
		if _, err := owned.Listen(context.Background(), "tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	owned.Close()
	for i, fake := range fakes {
		if got := fake.closes.Load(); got != 1 {
			t.Fatalf("listener %d closed %d times, want 1", i, got)
		}
	}
}
