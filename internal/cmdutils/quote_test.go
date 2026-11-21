package cmdutils

import (
	"errors"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/shlex"
)

// quoteCases carries, per row, words a shell or shlex would split, expand or drop unless quoted.
var quoteCases = []struct {
	name string
	argv []string
}{
	{"empty element", []string{"", "x", ""}},
	{"spaces and tabs", []string{"a b", " ", "\t", "a\tb", "  two  spaces  "}},
	{"single quotes", []string{"'", "it's", "''"}},
	{"double quotes", []string{`"`, `say "hi"`, `""`}},
	{"backslashes", []string{`\`, `a\b`, `\\`, `\n`, `trailing\`, `\'`, `\"`}},
	{"backticks", []string{"`", "`id`", "a`b"}},
	{"dollar signs", []string{"$", "$HOME", "${HOME}", "$(id)", "$1", "a$b"}},
	{"newlines", []string{"\n", "one\ntwo", "crlf\r\n"}},
	{"glob characters", []string{"*", "?", "[ab]", "*.go"}},
	{"semicolons, pipes and ampersands", []string{";", "a;b", "|", "a|b", "||", "&", "a&b", "&&"}},
	{"leading dashes", []string{"-", "-n", "--", "-e", "--flag"}},
	{"non-ASCII text", []string{"héllo", "日本語", "🙂", "a\u00a0b"}},
	{"other shell syntax", []string{"#x", "a#b", "~", "~/x", "{a,b}", "a=b", "(x)", "<", ">", "!"}},
}

func TestQuoteRoundTripsThroughShlex(t *testing.T) {
	for _, tc := range quoteCases {
		t.Run(tc.name, func(t *testing.T) {
			requireShlexRoundTrip(t, tc.argv)
		})
	}
}

func TestQuoteRoundTripsGeneratedArgvThroughShlex(t *testing.T) {
	alphabet := []rune("az09%+,-./:@_ \t\r\n'\"\\`$*?[]{}~#!=;&|<>()^é日\u00a0🙂")
	r := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		argv := make([]string, r.IntN(5))
		for i := range argv {
			word := make([]rune, r.IntN(7))
			for j := range word {
				word[j] = alphabet[r.IntN(len(alphabet))]
			}
			argv[i] = string(word)
		}
		requireShlexRoundTrip(t, argv)
	}
}

func requireShlexRoundTrip(t *testing.T, argv []string) {
	t.Helper()
	line := Quote(argv)
	got, err := shlex.Split(line)
	if err != nil {
		t.Fatalf("shlex.Split(%q) = %v, quoting %q", line, err, argv)
	}
	if !slices.Equal(got, argv) {
		t.Fatalf("shlex.Split(%q) = %q, want %q", line, got, argv)
	}
}

func TestQuoteRoundTripsThroughSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	sh, err := exec.LookPath("/bin/sh")
	if err != nil {
		t.Skipf("/bin/sh unavailable: %v", err)
	}
	// Every glob in the table matches a file here, so an unquoted one expands.
	dir := t.TempDir()
	for _, name := range []string{"a", "b.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range quoteCases {
		t.Run(tc.name, func(t *testing.T) {
			line := Quote(append([]string{"printf", `%s\0`}, tc.argv...))
			cmd := exec.Command(sh, "-c", line)
			cmd.Dir = dir
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("sh -c on %q: %v", line, err)
			}
			got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
			if !slices.Equal(got, tc.argv) {
				t.Fatalf("sh split %q into %q, want %q", line, got, tc.argv)
			}
		})
	}
}

func TestQuoteKeepsLeadingAssignmentACommandWord(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	sh, err := exec.LookPath("/bin/sh")
	if err != nil {
		t.Skipf("/bin/sh unavailable: %v", err)
	}
	// Left bare, sh would take NAME=value as an assignment and exit 0.
	line := Quote([]string{"NAME=value"})
	var exit *exec.ExitError
	if err := exec.Command(sh, "-c", line).Run(); !errors.As(err, &exit) || exit.ExitCode() != 127 {
		t.Fatalf("sh -c %q = %v, want exit 127 for a command named NAME=value that is not found", line, err)
	}
}

func TestQuoteLeavesPlainWordsUnquoted(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"nc", "-u", "example.org", "53"}, "nc -u example.org 53"},
		{[]string{"nc", "-l", "fe80::1%en0", "8080"}, "nc -l fe80::1%en0 8080"},
		{[]string{"nc", "-U", "/run/user/1000/proxy_1.sock"}, "nc -U /run/user/1000/proxy_1.sock"},
		{[]string{"nc", "-Ul", "/tmp/a+b,c@d.sock"}, "nc -Ul /tmp/a+b,c@d.sock"},
	} {
		if got := Quote(tc.argv); got != tc.want {
			t.Errorf("Quote(%q) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}

func TestQuoteOfNoWordsIsEmpty(t *testing.T) {
	if got := Quote(nil); got != "" {
		t.Fatalf("Quote(nil) = %q, want an empty line", got)
	}
}
