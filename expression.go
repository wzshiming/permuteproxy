package permuteproxy

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wzshiming/permuteproxy/internal/cmdutils"
)

// expression declares a network as adapters over another network, at an address its template makes from the declared one.
type expression struct {
	layers   []string // adapters, outermost first
	network  string
	opaque   bool // network takes an opaque address, written after ':' rather than "://"
	template string
}

// parseExpression reads text the way ParseURI reads a scheme and an address: [layer+...]network:template or [layer+...]network://template.
func parseExpression(text string) (expression, error) {
	scheme, rest, ok := strings.Cut(text, ":")
	tokens := strings.Split(scheme, "+")
	for _, t := range tokens {
		ok = ok && validName.MatchString(t)
	}
	template, authority := strings.CutPrefix(rest, "//")
	if !ok || template == "" || strings.ContainsFunc(template, isCTL) {
		return expression{}, fmt.Errorf("unparsable expression %q", text)
	}
	return expression{layers: tokens[:len(tokens)-1], network: tokens[len(tokens)-1], opaque: !authority, template: template}, nil
}

func isCTL(r rune) bool {
	return r < ' ' || r == 0x7f
}

// placeholders lists per AddressKind the letters a template may put after '%', besides the '%' that "%%" writes.
var placeholders = map[AddressKind]string{AddressHost: "hp", AddressPath: "h", AddressOpaque: "a"}

// check refuses a placeholder of x's template that is unknown, unfit for kind, or quoted or escaped for a shell.
func (x expression) check(kind AddressKind) error {
	t := x.template
	var quote byte // the quote a POSIX shell reading t is inside
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c == '%':
			p := t[i:min(i+2, len(t))]
			switch {
			case p == "%%":
			case len(p) < 2 || strings.IndexByte(placeholders[kind], p[1]) < 0:
				return fmt.Errorf("placeholder %q is unknown or does not fit the address", p)
			case quote != 0:
				return fmt.Errorf("placeholder %q is inside quotes", p)
			case i > 0 && t[i-1] == '\\':
				return fmt.Errorf("placeholder %q follows a backslash", p)
			}
			i++
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\' && i+1 < len(t) && t[i+1] != '%':
			i++
		case c == quote:
			quote = 0
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		}
	}
	return nil
}

// over is the chain of x's layers over its network at address.
func (x expression) over(address string) Chain {
	c := Chain{Endpoint: Endpoint{Network: x.network, Address: address}}
	for _, scheme := range x.layers {
		c.Layers = append(c.Layers, Layer{Scheme: scheme})
	}
	return c
}

// hostBytes are the bytes a host may carry into a template.
const hostBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_:%"

// expand fills x's template from address, an address of kind, refusing values the template cannot carry.
func (x expression) expand(kind AddressKind, address string) (string, error) {
	var pairs []string
	switch kind {
	case AddressHost:
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return "", errors.New("address is not host:port")
		}
		if strings.HasPrefix(host, "-") || strings.Trim(host, hostBytes) != "" {
			return "", errors.New("host starts with '-' or has a byte other than ASCII letters, digits, '.', '-', '_', ':' and '%'")
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", errors.New("port is not a decimal number from 0 to 65535")
		}
		pairs = []string{"%h", x.insert(host), "%p", x.insert(port)}
	case AddressPath:
		if address == "" || address[0] == '-' || !utf8.ValidString(address) || strings.ContainsFunc(address, unicode.IsControl) {
			return "", errors.New("path is empty, starts with '-', is not UTF-8 or has a control character")
		}
		pairs = []string{"%h", x.insert(address)}
	case AddressOpaque:
		if address == "" {
			return "", errors.New("empty address")
		}
		pairs = []string{"%a", address}
	}
	return strings.NewReplacer(append(pairs, "%%", "%")...).Replace(x.template), nil
}

// insert is how a value enters x's template: one quoted word in a command line, else verbatim; empty as no text.
func (x expression) insert(value string) string {
	if x.opaque && value != "" {
		return cmdutils.Quote([]string{value})
	}
	return value
}

// checkExpression parses text and checks it declares registered adapters over a network not itself declared by expression, with placeholders an address of kind fills.
func checkExpression(text string, kind AddressKind) (expression, error) {
	x, err := parseExpression(text)
	if err != nil {
		return x, err
	}
	for _, name := range x.layers {
		if spec, ok := lookupLayer(name); !ok || spec.Kind != KindAdapter {
			return x, fmt.Errorf("%q is not a registered adapter", name)
		}
	}
	switch ns, ok := lookupNetwork(x.network); {
	case !ok:
		return x, fmt.Errorf("%q is not a registered network", x.network)
	case ns.Dial != "":
		return x, fmt.Errorf("%q is itself declared by expression", x.network)
	case (ns.AddressKind == AddressOpaque) != x.opaque:
		return x, fmt.Errorf("unparsable expression %q for the address kind of %q", text, x.network)
	}
	return x, x.check(kind)
}

// expressionPlane checks the expressions spec declares and derives the one plane its Dial expression carries.
func expressionPlane(spec NetworkSpec) (Plane, error) {
	switch {
	case spec.Dial == "":
		return 0, errors.New("Listen without Dial")
	case spec.Plane != 0:
		return 0, errors.New("Plane set with Dial, which derives it")
	}
	dial, err := checkExpression(spec.Dial, spec.AddressKind)
	if err != nil {
		return 0, fmt.Errorf("Dial: %w", err)
	}
	if spec.Listen != "" {
		listen, err := checkExpression(spec.Listen, spec.AddressKind)
		if err != nil {
			return 0, fmt.Errorf("Listen: %w", err)
		}
		if listen.network != dial.network || !slices.Equal(listen.layers, dial.layers) {
			return 0, errors.New("Listen differs from Dial in its layers or network")
		}
	}
	plane, _, err := dial.offers()
	if err != nil {
		return 0, fmt.Errorf("Dial: %w", err)
	}
	return plane, nil
}

// offers is what x's layers offer over its network, or that network's own plane without layers, and which of those planes lose datagram boundaries.
func (x expression) offers() (planes, lossy Plane, err error) {
	r, err := x.over(x.template).resolve()
	if err != nil {
		return 0, 0, err
	}
	if len(r.planes) > 0 {
		return r.planes[0], r.planes[0] & r.specs[0].Lossy, nil
	}
	ns, _ := lookupNetwork(x.network)
	return ns.Plane, 0, nil
}
