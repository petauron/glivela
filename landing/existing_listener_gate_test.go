package landing

import (
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"strings"
	"testing"
)

func TestExistingIPv6ListenerHostGate(t *testing.T) {
	peer := PeerIdentity{ID: "peer", PublicKey: "nodekey:" + strings.Repeat("a", 64), Address: "100.64.0.2"}
	g, err := NewHostGate(peer, 12345, 1, glivela.PrivateTransport{PublicAddress: "2606:4700:4700::1111", Port: 24008})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(g.hostObjects())
	s := string(raw)
	if !strings.Contains(s, "ipv6_addr") || !strings.Contains(s, "ip6") || !strings.Contains(s, "24008") || strings.Contains(s, "ipv4_addr") {
		t.Fatal("gate family/port differs", s)
	}
}
