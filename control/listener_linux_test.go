package control

import (
	"strings"
	"testing"
)

func TestListenerReadinessRequiresOwnedListeningSocket(t *testing.T) {
	row := "0: 08004064:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000 997 0 12345\n"
	if !ownedTCPListener(strings.NewReader(row), "100.64.0.8", 1080, 997) {
		t.Fatal("owned listener rejected")
	}
	for name, data := range map[string]string{
		"other uid":        strings.Replace(row, "997", "996", 1),
		"established only": strings.Replace(row, " 0A ", " 01 ", 1),
		"other port":       strings.Replace(row, ":0438", ":0439", 1),
		"wildcard":         strings.Replace(row, "08004064", "00000000", 1),
		"other address":    strings.Replace(row, "08004064", "09004064", 1),
		"damaged":          "0: broken\n",
		"empty":            "",
	} {
		t.Run(name, func(t *testing.T) {
			if ownedTCPListener(strings.NewReader(data), "100.64.0.8", 1080, 997) {
				t.Fatal("unready or unowned socket accepted")
			}
		})
	}
}

func TestIPv6ListenerReadinessRequiresExactOwnedSocket(t *testing.T) {
	// /proc/net/tcp6 renders each 32-bit address word in host byte order.
	row := "0: 00470626000000470000000011110000:5DC1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 997 0 12345\n"
	if !ownedTCPListener(strings.NewReader(row), "2606:4700:4700::1111", 24001, 997) {
		t.Fatal("exact IPv6 listener rejected")
	}
	for _, changed := range []string{
		strings.Replace(row, "997", "996", 1),
		strings.Replace(row, " 0A ", " 01 ", 1),
		strings.Replace(row, ":5DC1", ":5DC2", 1),
		strings.Replace(row, "00470626000000470000000011110000", "00000000000000000000000000000000", 1),
	} {
		if ownedTCPListener(strings.NewReader(changed), "2606:4700:4700::1111", 24001, 997) {
			t.Fatal("unowned, wildcard or inactive IPv6 socket accepted")
		}
	}
}
