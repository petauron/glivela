package landing

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func fixturePlan() Plan {
	return Plan{Revision: 7, Address: "100.64.0.10", EgressIP: "192.168.50.2", Sources: []Source{{Address: "100.64.0.11", TCPOnly: true}, {Address: "100.64.0.12"}}}
}

func TestPlanRejectsExpandedTrust(t *testing.T) {
	for _, mutate := range []func(*Plan){
		func(p *Plan) { p.Address = "0.0.0.0" }, func(p *Plan) { p.EgressIP = "" }, func(p *Plan) { p.EgressIP = "100.64.0.99" },
		func(p *Plan) { p.Sources[0].Address = "100.64.0.0/10" }, func(p *Plan) { p.Sources[0].Address = p.Address }, func(p *Plan) { p.Sources = append(p.Sources, p.Sources[0]) },
		func(p *Plan) { p.Revision = 0 }, func(p *Plan) { p.EgressIP = "2001:4860::1" },
	} {
		p := fixturePlan()
		mutate(&p)
		if _, err := p.Render(); err == nil {
			t.Fatal("unsafe plan rendered")
		}
	}
}

func TestPlanDeterministicAndDenyByDefault(t *testing.T) {
	p := fixturePlan()
	first, err := p.Artifact()
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(p.Sources)
	second, err := p.Artifact()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Config, second.Config) || first.Validate() != nil {
		t.Fatal("unstable artifact")
	}
	var config struct {
		Outbounds []struct{ Tag, Protocol string }
		DNS       struct{ Servers []string }
		Routing   struct{ Rules []map[string]any }
	}
	if json.Unmarshal(first.Config, &config) != nil || config.Outbounds[0].Protocol != "blackhole" {
		t.Fatal("not deny by default")
	}
	if !slices.Equal(config.DNS.Servers, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Fatal("implicit system DNS")
	}
	if config.Routing.Rules[4]["network"] != "tcp" || config.Routing.Rules[5]["network"] != "tcp,udp" {
		t.Fatal("source capabilities changed")
	}
	policy, err := p.Firewall(990, "tailscale0")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(policy.objects())
	if bytes.Contains(raw, []byte(`1081`)) || bytes.Contains(raw, []byte(`1208`)) {
		t.Fatal("Dante UDP range leaked into Xray policy")
	}
}

func TestInternalResolverExceptionCannotAuthorizeBusinessTraffic(t *testing.T) {
	for _, egress := range []string{"192.168.50.2", "2606:4700::1111"} {
		p := fixturePlan()
		p.EgressIP = egress
		for i := range p.Sources {
			p.Sources[i].TCPOnly = true
		}
		raw, err := p.Render()
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			DNS       struct{ Tag, QueryStrategy string }
			Routing   struct{ Rules []map[string]any }
			Outbounds []map[string]any
		}
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		expected := map[string]any{"type": "field", "inboundTag": []any{"resolver"}, "ip": []any{"1.1.1.1/32", "1.0.0.1/32"}, "port": "53", "network": "tcp,udp", "outboundTag": "resolver"}
		if !reflect.DeepEqual(config.Routing.Rules[0], expected) || config.DNS.Tag != "resolver" {
			t.Fatal("resolver exception widened")
		}
		for _, rule := range config.Routing.Rules[1:] {
			if rule["outboundTag"] == "resolver" {
				t.Fatal("another path can use resolver outbound")
			}
			if rule["outboundTag"] == "egress" && !reflect.DeepEqual(rule["inboundTag"], []any{"landing"}) {
				t.Fatal("business grant can authorize internal DNS")
			}
		}
		if config.Outbounds[0]["protocol"] != "blackhole" {
			t.Fatal("unmatched requests no longer fail closed")
		}
		strategy := "UseIPv4"
		if egress == "2606:4700::1111" {
			strategy = "UseIPv6"
		}
		if config.DNS.QueryStrategy != strategy || config.Outbounds[1]["sendThrough"] != egress {
			t.Fatal("resolver exception changed business address family")
		}
	}
}

func TestOfficialLandingConfiguration(t *testing.T) {
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if binary == "" {
		t.Skip("verified official Xray required")
	}
	for _, ipv6 := range []bool{false, true} {
		p := fixturePlan()
		if ipv6 {
			p.EgressIP = "2001:4860::1"
			for i := range p.Sources {
				p.Sources[i].TCPOnly = true
			}
		}
		raw, err := p.Render()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err = exec.Command(binary, "run", "-test", "-config", path).Run(); err != nil {
			t.Fatal("official Xray rejected landing configuration", err)
		}
	}
}
