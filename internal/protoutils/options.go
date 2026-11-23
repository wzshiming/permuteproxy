package protoutils

import (
	"net/url"
	"slices"
)

// Userinfo builds URL credentials from the username and optional password options.
func Userinfo(opts map[string]string, userKey, passKey string) *url.Userinfo {
	username := opts[userKey]
	if username == "" {
		return nil
	}
	if password, ok := opts[passKey]; ok {
		return url.UserPassword(username, password)
	}
	return url.User(username)
}

// Values converts layer options to url.Values, leaving out the listed keys.
func Values(opts map[string]string, except ...string) url.Values {
	values := url.Values{}
	for key, value := range opts {
		if !slices.Contains(except, key) {
			values.Set(key, value)
		}
	}
	return values
}
