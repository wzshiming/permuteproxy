package cmdutils

import (
	"testing"
)

func TestNetcatTemplates(t *testing.T) {
	for _, tc := range []struct {
		name, got, want string
	}{
		{"NetcatDialTCP", NetcatDialTCP, "nc %h %p"},
		{"NetcatListenTCP", NetcatListenTCP, "nc -l %h %p"},
		{"NetcatDialUnix", NetcatDialUnix, "nc -U %h"},
		{"NetcatListenUnix", NetcatListenUnix, "nc -Ul %h"},
		{"NetcatDialUDP", NetcatDialUDP, "nc -u -w 30 %h %p"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}
