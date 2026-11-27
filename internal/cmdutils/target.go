package cmdutils

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// hostBytes are the bytes a host may carry into a command line.
const hostBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_:%"

// maxHost bounds the host a command line carries, since no DNS name is longer.
const maxHost = 255

// SplitTarget splits a host:port address whose host and port a command line can carry.
func SplitTarget(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return "", "", errors.New("address is not host:port")
	}
	if len(host) > maxHost {
		return "", "", fmt.Errorf("host of %d bytes is longer than %d", len(host), maxHost)
	}
	if strings.HasPrefix(host, "-") || strings.Trim(host, hostBytes) != "" {
		return "", "", errors.New("host starts with '-' or has a byte other than ASCII letters, digits, '.', '-', '_', ':' and '%'")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", "", errors.New("port is not a decimal number from 0 to 65535")
	}
	return host, port, nil
}
