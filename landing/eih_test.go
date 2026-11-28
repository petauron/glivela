package landing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
)

func testEIHKey16(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 16))
}

func eihDualRolePlan() Plan {
	return Plan{
		Revision: 3,
		Address:  "100.64.0.10",
		EgressIP: "192.168.50.2",
		EIHListeners: []EIHListener{
			{
				Address:   "9.9.9.9",
				Port:      glivela.RelayPoolPort,
				ServerKey: testEIHKey16(1),
				Users: []EIHUser{
					{
						ID:     "land-v4-tcp",
						Email:  "eih-land-v4-tcp",
						Key:    testEIHKey16(2),
						Source: "8.8.4.4",
						Role:   "landing",
					},
					{
						ID:       "land-v4-udp",
						Email:    "eih-land-v4-udp",
						Key:      testEIHKey16(3),
						Source:   "8.8.8.8",
						Role:     "landing",
						UDP:      true,
						EgressIP: "2001:4860:4860::8888",
					},
				},
			},
			{
				Address:   "2606:4700:4700::1111",
				Port:      glivela.RelayPoolPort,
				ServerKey: testEIHKey16(4),
				Users: []EIHUser{
					{
						ID:       "relay-v6-acc1",
						Email:    "eih-relay-v6-acc1",
						Key:      testEIHKey16(5),
						Source:   "2001:4860:4860::8844",
						Role:     "relay",
						EgressIP: "2606:4700:4700::1111",
						RelayTargets: []EIHRelayTarget{
							{Address: "2620:fe::fe", Port: glivela.RelayPoolPort},
							{Address: "2620:fe::9", Port: glivela.RelayPoolPort},
						},
					},
					{
						ID:     "land-v6-tcp",
						Email:  "eih-land-v6-tcp",
						Key:    testEIHKey16(6),
						Source: "2001:4860:4860::1111",
						Role:   "landing",
					},
				},
			},
		},
	}
}

func TestEIHListenerValidationAndRendering(t *testing.T) {
	p := eihDualRolePlan()
	if err := p.Validate(); err != nil {
		t.Fatalf("valid dual-role EIH plan rejected: %v", err)
	}
	if _, err := p.RenderVersion(31); err == nil {
		t.Fatal("legacy landing render version 31 accepted EIHListeners")
	}

	raw, err := p.Render()
	if err != nil {
		t.Fatalf("dual-role EIH Render failed: %v", err)
	}
	var cfg struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal EIH config: %v", err)
	}

	v4Tag := eihInboundTag("9.9.9.9")
	v6Tag := eihInboundTag("2606:4700:4700::1111")
	seenInbounds := map[string]int{}
	for _, in := range cfg.Inbounds {
		tag, _ := in["tag"].(string)
		if tag == v4Tag || tag == v6Tag {
			settings, _ := in["settings"].(map[string]any)
			clients, _ := settings["clients"].([]any)
			if in["protocol"] != "shadowsocks" || in["port"] != float64(glivela.RelayPoolPort) || settings["method"] != glivela.SS2022Method || settings["network"] != "tcp" || len(clients) != 2 {
				t.Fatalf("unexpected EIH inbound %s: %+v", tag, in)
			}
			seenInbounds[tag] = len(clients)
		}
	}
	if len(seenInbounds) != 2 {
		t.Fatalf("expected 2 single-port 24000 EIH inbounds, got %v", seenInbounds)
	}

	relayOutTag := eihRelayOutboundTag("2606:4700:4700::1111", "relay-v6-acc1")
	foundRelayOut := false
	for _, out := range cfg.Outbounds {
		if out["tag"] != relayOutTag {
			continue
		}
		foundRelayOut = true
		if out["protocol"] != "freedom" || out["sendThrough"] != "2606:4700:4700::1111" || out["streamSettings"] != nil {
			t.Fatalf("relay outbound must be direct freedom without dialerProxy: %+v", out)
		}
		settings, _ := out["settings"].(map[string]any)
		finalRules, _ := settings["finalRules"].([]any)
		if settings["targetStrategy"] != "ForceIPv6" || len(finalRules) != 3 {
			t.Fatalf("unexpected relay outbound finalRules: %+v", settings)
		}
		lastRule, _ := finalRules[2].(map[string]any)
		if lastRule["action"] != "block" {
			t.Fatalf("relay finalRules must terminate with block: %+v", lastRule)
		}
	}
	if !foundRelayOut {
		t.Fatal("dedicated relay freedom outbound missing")
	}

	relayTCPAllow, relayDeny, landingUDP443Deny := false, false, false
	for _, rule := range cfg.Routing.Rules {
		users, _ := rule["user"].([]any)
		if len(users) != 1 {
			continue
		}
		switch users[0] {
		case "eih-relay-v6-acc1":
			if rule["network"] == "tcp" && rule["outboundTag"] == relayOutTag {
				relayTCPAllow = true
			}
			if rule["network"] == nil && rule["outboundTag"] == "deny" {
				relayDeny = true
			}
		case "eih-land-v4-udp":
			if rule["network"] == "udp" && rule["port"] == "443" && rule["outboundTag"] == "deny" {
				landingUDP443Deny = true
			}
		}
	}
	if !relayTCPAllow || !relayDeny || !landingUDP443Deny {
		t.Fatalf("missing EIH routing policy: relayTCPAllow=%v relayDeny=%v landingUDP443Deny=%v", relayTCPAllow, relayDeny, landingUDP443Deny)
	}

	// Negative validation cases.
	for name, mutate := range map[string]func(*Plan){
		"server-socket-conflict": func(bad *Plan) {
			bad.Transport = glivela.PrivateTransport{Protocol: "ss2022", PublicAddress: "9.9.9.9", Port: glivela.RelayPoolPort, Key: testEIHKey16(9)}
			bad.Sources = []Source{{Address: "100.64.0.11", PublicAddress: "1.1.1.1", TCPOnly: true}}
		},
		"client-socket-conflict": func(bad *Plan) {
			bad.ClientListeners = []ClientListener{{ID: "cl-v6", Port: glivela.RelayPoolPort, Key: testEIHKey16(9), Source: "2001:4860:4860::8888", Address: "2606:4700:4700::1111", Transport: "ipv6-ss2022"}}
			bad.Transport = glivela.PrivateTransport{Protocol: "ss2022", PublicAddress: "1.1.1.1", Key: testEIHKey16(10)}
		},
		"relay-udp-forbidden": func(bad *Plan) {
			bad.EIHListeners[1].Users[0].UDP = true
		},
		"relay-empty-targets": func(bad *Plan) {
			bad.EIHListeners[1].Users[0].RelayTargets = nil
		},
		"relay-family-mismatch": func(bad *Plan) {
			bad.EIHListeners[1].Users[0].RelayTargets = []EIHRelayTarget{{Address: "1.1.1.1", Port: glivela.RelayPoolPort}}
		},
		"relay-private-target": func(bad *Plan) {
			bad.EIHListeners[1].Users[0].EgressIP = "192.168.50.2"
			bad.EIHListeners[1].Users[0].RelayTargets = []EIHRelayTarget{{Address: "192.168.50.9", Port: glivela.RelayPoolPort}}
		},
		"duplicate-user-key": func(bad *Plan) {
			bad.EIHListeners[0].Users[1].Key = bad.EIHListeners[0].Users[0].Key
		},
		"source-family-mismatch": func(bad *Plan) {
			bad.EIHListeners[0].Users[0].Source = "2001:4860:4860::8888"
		},
	} {
		bad := eihDualRolePlan()
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid EIH plan %s was accepted", name)
		}
	}

	// Non-EIH plan remains byte-identical across version 31 and current version 63.
	plain := Plan{Revision: 1, Address: "100.64.0.10", EgressIP: "192.168.50.2", Sources: []Source{{Address: "100.64.0.11", TCPOnly: true}}}
	r31, err := plain.RenderVersion(31)
	if err != nil {
		t.Fatal(err)
	}
	r63, err := plain.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r31, r63) {
		t.Fatal("non-EIH landing render changed across versions")
	}
}

func TestServerFirewallV4EIHPolicies(t *testing.T) {
	p := eihDualRolePlan()
	fw, err := p.Firewall(990, "eth0")
	if err != nil {
		t.Fatalf("EIH Firewall failed: %v", err)
	}
	table, marker := fw.identity()
	if !strings.HasPrefix(table, "glivela_landing_server_v4_") || !strings.HasPrefix(marker, "glivela-landing-server-v4:") {
		t.Fatalf("expected v4 firewall identity, got %s / %s", table, marker)
	}
	if !slices.Contains(fw.UDPEgressIPs, "2001:4860:4860::8888") {
		t.Fatalf("landing EIH UDP egress missing from UDPEgressIPs: %v", fw.UDPEgressIPs)
	}

	objs := fw.objects()
	hasV4InputAllow, hasV4InputDrop, hasV6RelayEgress, hasUDP443Drop := false, false, false, false
	for _, obj := range objs {
		rule := obj["rule"]
		if rule == nil {
			continue
		}
		raw, _ := json.Marshal(rule["expr"])
		text := string(raw)
		if rule["chain"] == "input" {
			if strings.Contains(text, `"9.9.9.9"`) && strings.Contains(text, `"8.8.4.4"`) && strings.Contains(text, `"return"`) {
				hasV4InputAllow = true
			}
			if strings.Contains(text, `"9.9.9.9"`) && strings.Contains(text, `24000`) && strings.Contains(text, `"drop"`) {
				hasV4InputDrop = true
			}
		}
		if rule["chain"] == "destinations" {
			if strings.Contains(text, `"2606:4700:4700::1111"`) && strings.Contains(text, `"2620:fe::fe"`) && strings.Contains(text, `24000`) && strings.Contains(text, `"return"`) {
				hasV6RelayEgress = true
			}
			if strings.Contains(text, `"udp"`) && strings.Contains(text, `443`) && strings.Contains(text, `"drop"`) {
				hasUDP443Drop = true
			}
		}
	}
	if !hasV4InputAllow || !hasV4InputDrop || !hasV6RelayEgress || !hasUDP443Drop {
		t.Fatalf("missing v4 nftables rules: allow=%v drop=%v relayEgress=%v udp443=%v", hasV4InputAllow, hasV4InputDrop, hasV6RelayEgress, hasUDP443Drop)
	}

	// Non-EIH firewall must retain v2 table identity.
	plainFW := testServerFirewall()
	plainTable, _ := plainFW.identity()
	if !strings.HasPrefix(plainTable, "glivela_landing_server_v2_") {
		t.Fatalf("non-EIH firewall identity changed: %s", plainTable)
	}
}

func TestServerFirewallV4DualNICRemoval(t *testing.T) {
	p := eihDualRolePlan()
	installed, err := p.Firewall(990, "tailscale0")
	if err != nil {
		t.Fatal(err)
	}
	// IPv4 and IPv6 EIH listeners sit on two distinct NICs (eth0 vs eth1).
	for i := range installed.EIHListeners {
		if strings.Contains(installed.EIHListeners[i].Address, ":") {
			installed.EIHListeners[i].Interface = "eth1"
		} else {
			installed.EIHListeners[i].Interface = "eth0"
		}
	}
	ownedTable, _ := installed.identity()
	foreignTable := map[string]nftObject{
		"table": {"family": "inet", "name": "glivela_landing_server_v4_deadbeef00000000", "comment": "glivela-landing-server-v4:" + strings.Repeat("f", 64)},
	}
	doc := nftDocument{Objects: append(slices.Clone(installed.objects()), foreignTable)}
	deleted := []string{}
	run := func(_ context.Context, input []byte, _ ...string) ([]byte, error) {
		if input == nil {
			return json.Marshal(doc)
		}
		var req struct {
			NFTables []struct {
				Delete struct {
					Table struct {
						Name string `json:"name"`
					} `json:"table"`
				} `json:"delete"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(input, &req); err != nil {
			t.Fatal(err)
		}
		for _, item := range req.NFTables {
			name := item.Delete.Table.Name
			if name == "" {
				continue
			}
			deleted = append(deleted, name)
			doc.Objects = slices.DeleteFunc(doc.Objects, func(obj map[string]nftObject) bool {
				for _, v := range obj {
					if v["name"] == name || v["table"] == name {
						return true
					}
				}
				return false
			})
		}
		return nil, nil
	}

	// Reconstructed removal candidate has empty per-listener interfaces (as after
	// IP unbind or rollback) and must still discover eth0+eth1 and remove ONLY ownedTable.
	candidate, err := p.Firewall(990, "tailscale0")
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.removeMatchingEIH(context.Background(), run); err != nil {
		t.Fatalf("dual-NIC EIH removal failed: %v", err)
	}
	if !slices.Equal(deleted, []string{ownedTable}) {
		t.Fatalf("expected only %s deleted, got %v", ownedTable, deleted)
	}
	if len(doc.Objects) != 1 || doc.Objects[0]["table"]["name"] != "glivela_landing_server_v4_deadbeef00000000" {
		t.Fatalf("foreign v4 table was unexpectedly altered: %+v", doc.Objects)
	}
}

func testOfficialEIHLandingConfiguration(t *testing.T, binary string) {
	t.Helper()
	p := eihDualRolePlan()
	raw, err := p.Render()
	if err != nil {
		t.Fatalf("render dual-role EIH plan: %v", err)
	}
	path := filepath.Join(t.TempDir(), "eih-landing.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("official Xray rejected dual-role EIH landing configuration: %v\n%s", err, string(out))
	}
}
