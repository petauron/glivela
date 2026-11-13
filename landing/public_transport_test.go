package landing

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
	gate, err := NewHostGate(peer, 12345, 3, glivela.PrivateTransport{PublicAddress: "8.8.8.8"})
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

func sharedPublicServerPlan() Plan {
	key := "AAECAwQFBgcICQoLDA0ODw=="
	return Plan{Revision: 4, Address: "100.64.0.2", EgressIP: "8.8.4.4",
		Transport:       glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: "8.8.8.8", Port: 24000},
		Sources:         []Source{{Address: "100.64.0.3", PublicAddress: "1.1.1.1", TCPOnly: true}, {Address: "100.64.0.4", PublicAddress: "9.9.9.9", TCPOnly: true}},
		ClientListeners: []ClientListener{{ID: "client-example", Shared: true, Transport: glivela.IPv4ClientSS2022, Port: 24000, Key: key, Source: "1.1.1.1"}}}
}

func TestSharedPublicServerSocketPreservesMigratedSources(t *testing.T) {
	for _, keepClient := range []bool{true, false} {
		p := sharedPublicServerPlan()
		if !keepClient {
			p.ClientListeners = nil
		}
		raw, err := p.Render()
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Inbounds []struct {
				Port     int
				Listen   string
				Protocol string
			}
		}
		if json.Unmarshal(raw, &config) != nil || len(config.Inbounds) != 1 || config.Inbounds[0].Port != 24000 || config.Inbounds[0].Listen != "8.8.8.8" || config.Inbounds[0].Protocol != "shadowsocks" {
			t.Fatal("expected one authenticated public socket")
		}
		if !strings.Contains(string(raw), "9.9.9.9/32") || !strings.Contains(string(raw), "1.1.1.1/32") || strings.Contains(string(raw), `"port":1080`) {
			t.Fatal("lost a source or reopened 1080")
		}
		fw, err := p.Firewall(12345, "eth0")
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range fw.objects() {
			r := object["rule"]
			if r == nil || r["chain"] != "input" {
				continue
			}
			expr, _ := json.Marshal(r["expr"])
			if strings.Contains(string(expr), "24000") && strings.Contains(string(expr), `"drop"`) {
				t.Fatal("client-only terminal drop blocks server source")
			}
		}
	}
	p := sharedPublicServerPlan()
	for _, mutate := range []func(*Plan){
		func(p *Plan) { p.ClientListeners[0].Key = "AQEBAQEBAQEBAQEBAQEBAQ==" },
		func(p *Plan) { p.ClientListeners[0].Shared = false },
		func(p *Plan) { p.ClientListeners[0].EgressIP = "1.0.0.1" },
		func(p *Plan) { p.Sources[1].TCPOnly = false },
		func(p *Plan) { p.Transport.Port = 24001 },
		func(p *Plan) { p.Transport.PublicAddress = "100.64.0.2" },
	} {
		bad := p
		bad.ClientListeners = append([]ClientListener(nil), p.ClientListeners...)
		bad.Sources = append([]Source(nil), p.Sources...)
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted conflicting shared socket")
		}
	}
}

func testOfficialSharedPublicServerSocket(t *testing.T, binary string) {
	t.Helper()
	raw, err := sharedPublicServerPlan().Render()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shared-public.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("official core rejected shared socket: %s: %v", output, err)
	}
}

// Different listeners at one authorized public IP are independent paths.
func TestPublicGatePreservesDistinctListenerPorts(t *testing.T) {
	for _, ports := range [][2]int{{1080, 24000}, {24006, 24000}} {
		for _, address := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
			peer := PeerIdentity{ID: "peer", PublicKey: "nodekey:peer", Address: "100.64.0.2"}
			other, err := NewHostGate(peer, 12345, 3, glivela.PrivateTransport{PublicAddress: address, Port: ports[0]})
			if err != nil {
				t.Fatal(err)
			}
			current, err := NewHostGate(peer, 12345, 4, glivela.PrivateTransport{PublicAddress: address, Port: ports[1]})
			if err != nil {
				t.Fatal(err)
			}
			document := fixtureNFT(t, other)
			document.Objects = append(document.Objects, fixtureNFT(t, current).Objects...)
			writes := 0
			current.run = func(_ context.Context, input []byte, _ ...string) ([]byte, error) {
				if input != nil {
					writes++
				}
				return json.Marshal(document)
			}
			if err := current.RemoveClosedConflicts(context.Background()); err != nil || writes != 0 {
				t.Fatal("distinct listener treated as conflicting", ports, address, err)
			}
		}
	}
}
