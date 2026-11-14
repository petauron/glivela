package landing

import (
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"strings"
	"testing"
)

func TestPrivateServerHostGateRequiresExactBinding(t *testing.T) {
	peer := PeerIdentity{ID: "landing", PublicKey: strings.Repeat("a", 64), Address: "100.64.0.2"}
	link := &glivela.PrivateClientLink{Source: "10.20.0.3", Address: "10.20.0.2", SourceInterface: "ens8", Interface: "ens8"}
	transport := glivela.PrivateTransport{Protocol: "ss2022", Key: "MDEyMzQ1Njc4OWFiY2RlZg==", PublicAddress: link.Address, Port: 24000, ClientListenerID: "existing-client", PrivateLink: link}
	gate, err := NewHostGate(peer, 12345, 1, transport)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(gate.hostObjects())
	if !strings.Contains(string(raw), link.Address) || !strings.Contains(string(raw), "24000") {
		t.Fatal("gate lost exact private socket")
	}
	transport.PrivateLink = nil
	if _, err = NewHostGate(peer, 12345, 1, transport); err == nil {
		t.Fatal("unbound private target accepted")
	}
	transport.PrivateLink = link
	transport.PublicAddress = "8.8.8.8"
	if _, err = NewHostGate(peer, 12345, 1, transport); err == nil {
		t.Fatal("mismatched private binding accepted")
	}
}
