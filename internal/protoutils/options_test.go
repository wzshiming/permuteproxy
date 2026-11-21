package protoutils

import (
	"net/url"
	"testing"
)

func TestUserinfo(t *testing.T) {
	tests := []struct {
		opts map[string]string
		want *url.Userinfo
	}{
		{nil, nil},
		{map[string]string{"password": "p"}, nil},
		{map[string]string{"username": ""}, nil},
		{map[string]string{"username": "u"}, url.User("u")},
		{map[string]string{"username": "u", "password": ""}, url.UserPassword("u", "")},
		{map[string]string{"username": "u", "password": "p"}, url.UserPassword("u", "p")},
	}
	for _, tt := range tests {
		got := Userinfo(tt.opts, "username", "password")
		if got.String() != tt.want.String() || (got == nil) != (tt.want == nil) {
			t.Fatalf("Userinfo(%v) = %v, want %v", tt.opts, got, tt.want)
		}
	}
}

func TestValues(t *testing.T) {
	opts := map[string]string{"username": "u", "password": "p", "identity_file": "id", "timeout": ""}
	got := Values(opts, "username", "password")
	if got.Encode() != "identity_file=id&timeout=" {
		t.Fatalf("Values = %q", got.Encode())
	}
	if len(opts) != 4 {
		t.Fatal("Values mutated its input")
	}
}
