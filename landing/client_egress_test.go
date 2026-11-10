package landing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func dualEgressFixture() Plan {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	return Plan{Revision: 8, Address: "100.64.0.10", EgressIP: "2606:4700::100",
		Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: "9.9.9.9"},
		Sources:   []Source{{Address: "100.64.0.11", PublicAddress: "1.1.1.1", TCPOnly: true}},
		ClientListeners: []ClientListener{
			{ID: "retained-relay", Port: 24000, Transport: "ipv6-ss2022", Address: "2606:4700::200", Source: "2001:4860:4860::8888", Key: key},
			{ID: "client-v6-transport", Port: 24001, Transport: "ipv6-ss2022", Address: "2606:4700::200", Source: "2001:4860:4860::8888", Key: key, EgressIP: "9.9.9.9"},
			{ID: "client-v4-transport", Port: 24002, Transport: glivela.IPv4ClientSS2022, Source: "1.1.1.1", Key: base64.StdEncoding.EncodeToString(make([]byte, 32)), EgressIP: "9.9.9.9"},
		}}
}

func TestSingleLandingBindsEachClientExitAndKeepsRelay(t *testing.T) {
	p := dualEgressFixture()
	if _, err := p.RenderVersion(5); err == nil {
		t.Fatal("old format accepted per-client exit")
	}
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag  string
			Port int
		}
		Outbounds []map[string]any
		DNS       struct{ QueryStrategy string }
		Routing   struct {
			DomainStrategy string
			Rules          []map[string]any
		}
	}
	if err = json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 4 || config.Inbounds[0].Port != 1080 || len(config.Outbounds) != 4 || config.Outbounds[1]["sendThrough"] != p.EgressIP || config.Outbounds[3]["sendThrough"] != "9.9.9.9" {
		t.Fatal("default listener or fixed exits changed")
	}
	if config.DNS.QueryStrategy != "UseIP" || config.Routing.DomainStrategy != "AsIs" {
		t.Fatal("DNS is not selected by the bound outbound")
	}
	for i, want := range map[int]string{1: "ForceIPv6", 3: "ForceIPv4"} {
		settings := config.Outbounds[i]["settings"].(map[string]any)
		if settings["targetStrategy"] != want || len(settings["finalRules"].([]any)) != 1 {
			t.Fatal("exit can silently fall back or skip final destination guard")
		}
	}
	grants := map[string]string{}
	for _, r := range config.Routing.Rules {
		tag, _ := r["outboundTag"].(string)
		if tag == "deny" || tag == "resolver" {
			continue
		}
		inbound := r["inboundTag"].([]any)[0].(string)
		grants[inbound] = tag
		if _, ok := r["source"]; !ok {
			t.Fatal("unscoped route")
		}
	}
	if grants["client-chain-retained-relay"] != "egress" || grants["client-chain-client-v6-transport"] != clientEgressTag("9.9.9.9") || grants["client-chain-client-v4-transport"] != clientEgressTag("9.9.9.9") {
		t.Fatal("transport family selected the wrong final exit")
	}
	policy, err := p.Firewall(991, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	objects, _ := json.Marshal(policy.objects())
	if !bytes.Contains(objects, []byte(p.EgressIP)) || !bytes.Contains(objects, []byte("9.9.9.9")) {
		t.Fatal("one authorized source missing from kernel policy")
	}
	for _, o := range policy.objects() {
		r := o["rule"]
		if r == nil || r["chain"] != "destinations" {
			continue
		}
		b, _ := json.Marshal(r["expr"])
		v := string(b)
		if strings.Contains(v, `"right":"9.9.9.9"`) && strings.Contains(v, `"key":"l4proto"`) && strings.Contains(v, `"right":"udp"`) {
			t.Fatal("client override authorized UDP")
		}
	}
	bad := p
	bad.ClientListeners = append([]ClientListener(nil), p.ClientListeners...)
	bad.ClientListeners[1].EgressIP = "100.64.0.99"
	if bad.Validate() == nil {
		t.Fatal("mesh exit accepted")
	}
	bad.ClientListeners[1].EgressIP = "9.9.9.9"
	bad.ClientListeners[1].Source = "::/0"
	if bad.Validate() == nil {
		t.Fatal("wildcard source accepted")
	}
	for i := range p.ClientListeners {
		p.ClientListeners[i].EgressIP = ""
	}
	old, err := p.RenderVersion(4)
	if err != nil {
		t.Fatal(err)
	}
	current, err := p.Render()
	if err != nil || !bytes.Equal(old, current) {
		t.Fatal("unchanged runtime bytes changed")
	}
}

func TestOfficialDualEgressLandingConfiguration(t *testing.T) {
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if binary == "" {
		t.Skip("verified official Xray required")
	}
	raw, err := dualEgressFixture().Render()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dual-egress.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("official Xray rejected single-instance exits: %v %s", err, out)
	}
}
