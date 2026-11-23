package permuteproxy

import (
	"errors"
	"fmt"
	"sync"
)

// closeOnce calls release, when set, and then closes inner, both at most once.
func closeOnce(release func() error, inner Transport) func() error {
	return sync.OnceValue(func() error {
		var err error
		if release != nil {
			err = release()
		}
		return errors.Join(err, closeIf(inner))
	})
}

// reject calls release, when set, for a declaration the root package refuses, and marks err as an invalid chain unless it is one.
func reject(release func() error, err error) error {
	if release != nil {
		release()
	}
	if errors.Is(err, ErrInvalidChain) {
		return err
	}
	return invalid(err)
}

func invalid(err error) error {
	return fmt.Errorf("%w: %w", err, ErrInvalidChain)
}
