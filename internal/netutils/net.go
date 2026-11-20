package netutils

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

var ErrServerClosed = fmt.Errorf("server closed")

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
