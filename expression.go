package permuteproxy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// A URI ends its address at '?' or '#', admits no control bytes and reads an opaque part starting with '/' as a path.
	if !ok || template == "" || strings.ContainsAny(template, "?#") || strings.ContainsFunc(template, isCTL) || !authority && template[0] == '/' {
		return expression{}, fmt.Errorf("unparsable expression %q", text)
	}
	return expression{layers: tokens[:len(tokens)-1], network: tokens[len(tokens)-1], opaque: !authority, template: template}, nil
}

func isCTL(r rune) bool {
	return r < ' ' || r == 0x7f
}

// placeholders lists per AddressKind the letters a template may put after '%', besides the '%' that "%%" writes.
var placeholders = map[AddressKind]string{AddressHost: "hp", AddressPath: "h", AddressOpaque: "a"}

// check refuses a placeholder of x's template that is unknown or that an address of kind does not fill.
func (x expression) check(kind AddressKind) error {
	for rest := x.template; ; {
		i := strings.IndexByte(rest, '%')
		if i < 0 {
			return nil
		}
		if i+1 == len(rest) || rest[i+1] != '%' && strings.IndexByte(placeholders[kind], rest[i+1]) < 0 {
			return fmt.Errorf("placeholder %q is unknown or does not fit the address", rest[i:min(i+2, len(rest))])
		}
		rest = rest[i+2:]
	}
}

// over is the chain of x's layers over its network at address.
func (x expression) over(address string) Chain {
	c := Chain{Endpoint: Endpoint{Network: x.network, Address: address}}
	for _, scheme := range x.layers {
		c.Layers = append(c.Layers, Layer{Scheme: scheme})
	}
	return c
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
	r, err := dial.over(dial.template).resolve()
	if err != nil {
		return 0, fmt.Errorf("Dial: %w", err)
	}
	if len(r.planes) > 0 {
		return r.planes[0], nil
	}
	ns, _ := lookupNetwork(dial.network)
	return ns.Plane, nil
}
