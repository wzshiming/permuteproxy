package cmdutils

import (
	"strings"
)

// plain characters need no quoting; '=' is left out since a leading NAME=value is an assignment.
const plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%+,-./:@_"

// Quote joins argv into a line a POSIX shell, and shlex.Split for valid UTF-8, split back into argv; plain words stay bare.
func Quote(argv []string) string {
	words := make([]string, len(argv))
	for i, word := range argv {
		if word == "" || strings.Trim(word, plain) != "" {
			word = "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
		}
		words[i] = word
	}
	return strings.Join(words, " ")
}
