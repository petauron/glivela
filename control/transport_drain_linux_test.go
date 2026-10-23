//go:build linux

package control

import (
	"strings"
	"testing"
)

func TestTransportDrainRequiresNoOwnedBusinessSockets(t *testing.T) {
	row := func(local, state, inode string) string {
		return " 0: " + local + " 00000000:0000 " + state + " 0:0 00:0 0 1001 0 " + inode + "\n"
	}
	owned := map[string]bool{"10": true, "11": true}
	api := row("0100007F:2765", "0A", "10")
	for _, test := range []struct {
		name, network, raw string
		want               bool
	}{
		{"api only", "tcp", api, true},
		{"other service", "tcp", api + row("00000000:01BB", "01", "99"), true},
		{"active tcp", "tcp", api + row("0100007F:01BB", "01", "11"), false},
		{"remaining proxy listener", "tcp", api + row("0100007F:01BB", "0A", "11"), false},
		{"api request still active", "tcp", api + row("0100007F:2765", "01", "11"), false},
		{"active udp", "udp", row("00000000:01BB", "07", "11"), false},
		{"active ipv6", "tcp6", row("00000000000000000000000000000000:01BB", "01", "11"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := drainedSocketTable(strings.NewReader(test.raw), owned, test.network)
			if err != nil || got != test.want {
				t.Fatal(got, err)
			}
		})
	}
	if _, err := drainedSocketTable(strings.NewReader("truncated\n"), owned, "tcp"); err == nil {
		t.Fatal("malformed socket evidence accepted")
	}
}
