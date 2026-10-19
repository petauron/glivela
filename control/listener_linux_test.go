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
