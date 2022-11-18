package netutils

import (
	"errors"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"
)

var ErrServerClosed = errors.New("server closed")

// IsServerClosedError reports whether err is an error from server closed.
func IsServerClosedError(err error) bool {
	if err == nil {
		return false
	}

	if err == http.ErrServerClosed || err == ErrServerClosed || strings.Contains(strings.ToLower(err.Error()), ErrServerClosed.Error()) {
		return true
	}

	return false
}

var ErrClosedConn = errors.New("use of closed network connection")

// IsClosedConnError reports whether err is an error from use of a closed network connection.
func IsClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	if err == ErrClosedConn || strings.Contains(strings.ToLower(err.Error()), ErrClosedConn.Error()) {
		return true
	}

	if runtime.GOOS == "windows" {
		if oe, ok := err.(*net.OpError); ok && oe.Op == "read" {
			if se, ok := oe.Err.(*os.SyscallError); ok && se.Syscall == "wsarecv" {
				const WSAECONNABORTED = 10053
				const WSAECONNRESET = 10054
				if n := errno(se.Err); n == WSAECONNRESET || n == WSAECONNABORTED {
					return true
				}
			}
		}
	}
	return false
}

func errno(v error) uintptr {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Uintptr {
		return uintptr(rv.Uint())
	}
	return 0
}

var ErrAcceptTimeout = errors.New("i/o timeout")

// IsAcceptTimeoutError reports whether err is an error from use of a accept timeout.
func IsAcceptTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	if err == ErrAcceptTimeout || strings.Contains(err.Error(), ErrAcceptTimeout.Error()) {
		return true
	}

	if oe, ok := err.(*net.OpError); ok && oe.Op == "accept" {
		return IsAcceptTimeoutError(oe.Err)
	}

	return false
}
