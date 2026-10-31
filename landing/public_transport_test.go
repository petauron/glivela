package landing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestPublicLandingRetainsEgressAndExactSources(t *testing.T) {
	p := Plan{Revision: 3, Address: "100.64.0.2", EgressIP: "2606:4700:4700::1111", Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw==", PublicAddress: "8.8.8.8"}, Sources: []Source{{Address: "100.64.0.3", PublicAddress: "1.1.1.1", TCPOnly: true}}}
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds  []struct{ Listen string }
		Outbounds []struct {
			Tag         string
			SendThrough string
		}
	}
	if json.Unmarshal(raw, &config) != nil || config.Inbounds[0].Listen != "8.8.8.8" || config.Outbounds[1].SendThrough != p.EgressIP || !strings.Contains(string(raw), `"1.1.1.1/32"`) || strings.Contains(string(raw), "100.64.0.3") {
		t.Fatal("public listener changed identity or egress policy")
	}
	fw, err := p.Firewall(12345, "eth0")
	if err != nil || !fw.Public || fw.Sources[0] != "1.1.1.1" || fw.TCPOnlySources[0] != "1.1.1.1" {
		t.Fatal("public allowlist differs", err)
	}
	for _, bad := range []string{"0.0.0.0", "100.64.0.3", "10.0.0.1", "1.1.1.0/24", "example.com", "8.8.8.8"} {
		p.Sources[0].PublicAddress = bad
		if p.Validate() == nil {
			t.Fatal("unsafe public source accepted", bad)
		}
	}
}

func TestPublicGateKeepsManagementIdentitySeparate(t *testing.T) {
	peer := PeerIdentity{ID: "peer", PublicKey: "nodekey:peer", Address: "100.64.0.2"}
	gate, err := NewHostGate(peer, 12345, 3, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(gate.objects())
	if gate.peer != peer || !strings.Contains(string(raw), "8.8.8.8") || strings.Contains(string(raw), "100.64.0.2") {
		t.Fatal("gate conflates management and data endpoints")
	}
	now := time.Now().UTC()
	direct := LinkResult{State: "direct", Reason: "fresh_disco_direct_response", StartedAt: now.Add(-time.Second), CheckedAt: now}
	if gate.validLink(direct, now) {
		t.Fatal("private link accepted as public data evidence")
	}
	identity := direct
	identity.State, identity.Reason = "authenticated", "management_identity_verified"
	if !gate.validLink(identity, now) {
		t.Fatal("management identity refused")
	}
	private, _ := NewHostGate(peer, 12345, 3)
	if private.validLink(identity, now) {
		t.Fatal("identity-only evidence accepted for private data path")
	}
}
