package landing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
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
	if config.Routing.Rules[3]["network"] != "tcp" || config.Routing.Rules[4]["network"] != "tcp,udp" {
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
			DNS struct {
				Tag, QueryStrategy string
				Servers            []string
			}
			Routing   struct{ Rules []map[string]any }
			Outbounds []map[string]any
		}
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		expected := map[string]any{"type": "field", "inboundTag": []any{"resolver"}, "ip": []any{"1.1.1.1/32", "1.0.0.1/32"}, "port": "53", "network": "tcp,udp", "outboundTag": "resolver"}
		servers := []string{"1.1.1.1", "1.0.0.1"}
		if egress == "2606:4700::1111" {
			servers = []string{"tcp://[2606:4700:4700::1111]", "tcp://[2606:4700:4700::1001]"}
			expected["ip"] = []any{"2606:4700:4700::1111/128", "2606:4700:4700::1001/128"}
			expected["network"] = "tcp"
			if config.Outbounds[2]["sendThrough"] != egress {
				t.Fatal("IPv6 resolver lost the authorized fixed source")
			}
		} else if _, bound := config.Outbounds[2]["sendThrough"]; bound {
			t.Fatal("IPv4 resolver behavior changed")
		}
		if !reflect.DeepEqual(config.DNS.Servers, servers) || !reflect.DeepEqual(config.Routing.Rules[0], expected) || config.DNS.Tag != "resolver" {
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
	testOfficialSharedPublicServerSocket(t, binary)
	for _, ipv6 := range []bool{false, true} {
		p := fixturePlan()
		if ipv6 {
			p.EgressIP = "2001:4860::1"
			for i := range p.Sources {
				p.Sources[i].TCPOnly = true
			}
		}
		for _, withClient := range []bool{false, true} {
			candidate := p
			candidate.Sources = append([]Source(nil), p.Sources...)
			if withClient {
				candidate.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
				for i := range candidate.Sources {
					candidate.Sources[i].PublicAddress = []string{"1.1.1.1", "8.8.8.8"}[i]
				}
				candidate.ClientListeners = []ClientListener{{ID: "client-a", Port: 24001, Source: "2001:4860:4860::8888", Address: "2606:4700:4700::1111", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Transport: "ipv6-ss2022"}}
				candidate.ClientListeners = []ClientListener{
					{ID: "client-v6-a", Shared: true, Port: 24000, Source: "2001:4860:4860::8888", Address: "2606:4700:4700::1111", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Transport: "ipv6-ss2022"},
					{ID: "client-v6-b", Shared: true, Port: 24000, Source: "2001:4860:4860::8844", Address: "2606:4700:4700::1111", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Transport: "ipv6-ss2022"},
					{ID: "client-v4-a", Shared: true, Port: 24000, Source: candidate.Sources[0].PublicAddress, Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Transport: glivela.IPv4ClientSS2022},
					{ID: "client-v4-b", Shared: true, Port: 24000, Source: candidate.Sources[1].PublicAddress, Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Transport: glivela.IPv4ClientSS2022},
				}
				policy, err := candidate.Firewall(990, "eth0")
				if err != nil {
					t.Fatal(err)
				}
				accepted := map[string]int{}
				denied := map[string]bool{}
				for _, obj := range policy.objects() {
					r := obj["rule"]
					if r == nil || r["chain"] != "input" {
						continue
					}
					raw, _ := json.Marshal(r["expr"])
					text := string(raw)
					for _, address := range []string{candidate.Transport.PublicAddress, "2606:4700:4700::1111"} {
						if !strings.Contains(text, address) || !strings.Contains(text, "24000") {
							continue
						}
						if strings.Contains(text, `"return"`) {
							if denied[address] {
								t.Fatal("authorized source follows deny")
							}
							accepted[address]++
						}
						if strings.Contains(text, `"drop"`) {
							if accepted[address] != 2 {
								t.Fatal("shared listener missing an exact source")
							}
							denied[address] = true
						}
					}
				}
				if len(denied) != 2 {
					t.Fatal("shared listeners lack final deny")
				}
				bad := candidate
				bad.ClientListeners = slices.Clone(candidate.ClientListeners)
				bad.ClientListeners[1].Key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
				if bad.Validate() == nil {
					t.Fatal("mixed shared credentials accepted")
				}
			}
			raw, err := candidate.Render()
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
}

// Digests captured from the immutable pre-DNS-policy source, with the retired
// SSH policy present so render 1 must continue stripping it independently of
// whichever version is current.
func TestHistoricalLandingRenderDigestsRemainImmutable(t *testing.T) {
	p := fixturePlan()
	p.EgressIP = "2606:4700::100"
	for i := range p.Sources {
		p.Sources[i].TCPOnly = true
	}
	p.PublicSSH = &glivela.PublicSSHPolicy{AddressesComplete: true, HostPublicAddresses: []string{p.EgressIP}}
	for version, digest := range map[uint8]string{
		0: "6f9d0d5604e3d004e4f75a7dc14c52e20b202005bca44a83b8cbda099b7ee6d4",
		1: "33bbad7921cc1442ecfbe8b43df1be949b1bd0909ce345399e110ea800ede24a",
	} {
		a, err := p.ArtifactVersion(version)
		if err != nil || a.ConfigSHA256 != digest || a.Validate() != nil {
			t.Fatal("historical artifact changed", version, err)
		}
	}
}
