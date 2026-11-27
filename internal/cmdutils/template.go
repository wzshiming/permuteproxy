package cmdutils

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Template is a command line filled per target: %h is the host, or the socket path for
// unix, %p the port, empty for unix, %n the network and "%%" a '%'.
type Template string

// Check refuses an empty line and a '%' that starts no placeholder.
func (t Template) Check() error {
	if t == "" {
		return errors.New("empty command")
	}
	for i := 0; i < len(t); i++ {
		if t[i] != '%' {
			continue
		}
		p := string(t[i:min(i+2, len(t))])
		if len(p) < 2 || strings.IndexByte("hpn%", p[1]) < 0 {
			return fmt.Errorf("placeholder %q is unknown", p)
		}
		i++
	}
	return nil
}

// Fill writes the command line for address on network, a tcp or unix one; any other is refused
// with errors.ErrUnsupported. The values enter verbatim, wherever the template puts them, quotes
// and sh -c included, so only those every shell reads as plain text are taken: however often the
// line is parsed again, as by ssh, a value stays within its word.
func (t Template) Fill(network, address string) (string, error) {
	var host, port string
	switch network {
	case "tcp", "tcp4", "tcp6":
		var err error
		if host, port, err = SplitTarget(address); err != nil {
			return "", err
		}
	case "unix":
		if address == "" || address[0] == '-' || !utf8.ValidString(address) || !Plain(address) {
			return "", errors.New("path is empty, starts with '-' or has a byte other than ASCII letters, digits and \"%+,-./:@_\"")
		}
		host = address
	default:
		return "", errors.ErrUnsupported
	}
	return strings.NewReplacer("%h", host, "%p", port, "%n", network, "%%", "%").Replace(string(t)), nil
}
