package landing

import (
	"bytes"
	"encoding/json"
	"testing"

	glivela "github.com/petauron/glivela"
)

func udpSSPlan() Plan {
	return Plan{Revision: 1, Address: "100.64.0.10", EgressIP: "192.168.50.2", Transport: glivela.PrivateTransport{Protocol: "ss2022", PublicAddress: "9.9.9.9", Key: "MDEyMzQ1Njc4OWFiY2RlZg=="}, Sources: []Source{{Address: "100.64.0.11", PublicAddress: "8.8.4.4", TCPOnly: true, UDPOverTCP: true}}}
}

func TestUDPOverTCPAuthorization(t *testing.T) {
	for _, ip := range []string{"192.168.50.2", "2001:4860:4860::8888"} {
		p := udpSSPlan()
		p.EgressIP = ip
		raw, err := p.Render()
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Inbounds []struct{ Settings struct{ Network string } }
			Routing  struct{ Rules []map[string]any }
		}
		if json.Unmarshal(raw, &config) != nil || config.Inbounds[0].Settings.Network != "tcp" {
			t.Fatal("public UDP listener added")
		}
		allow := false
		deny443 := false
		for _, r := range config.Routing.Rules {
			if r["network"] == "tcp,udp" && r["outboundTag"] == "egress" {
				allow = true
			}
			if r["network"] == "udp" && r["port"] == "443" && r["outboundTag"] == "deny" {
				deny443 = true
			}
		}
		if !allow || !deny443 {
			t.Fatal("missing inner UDP rule or QUIC guard")
		}
		policy, err := p.Firewall(12345, "eth0")
		if err != nil || len(policy.UDPEgressIPs) != 1 || policy.UDPEgressIPs[0] != ip {
			t.Fatal("UDP egress authorization missing", err)
		}
		if _, err := p.RenderVersion(7); err == nil {
			t.Fatal("old runtime accepted new policy")
		}
		p.Sources[0].UDPOverTCP = false
		legacy, err := p.RenderVersion(7)
		if err != nil {
			t.Fatal(err)
		}
		current, err := p.Render()
		if err != nil || !bytes.Equal(legacy, current) {
			t.Fatal("default rendering changed", err)
		}
		policy, err = p.Firewall(12345, "eth0")
		if err != nil || len(policy.UDPEgressIPs) != 0 {
			t.Fatal("revoked UDP exit retained", err)
		}
	}
	for _, bad := range []func(*Plan){func(p *Plan) { p.Transport = glivela.PrivateTransport{}; p.Sources[0].PublicAddress = "" }, func(p *Plan) { p.Sources[0].TCPOnly = false }, func(p *Plan) { p.UDPOverTCPListeners = []string{"missing"} }} {
		p := udpSSPlan()
		bad(&p)
		if p.Validate() == nil {
			t.Fatal("unowned UDP capability accepted")
		}
	}
}

func TestUDPSharedListenerRetainsExactSource(t *testing.T) {
	p := udpSSPlan()
	p.Transport.Port = 24000
	p.Sources[0].UDPOverTCP = false
	p.Sources = append(p.Sources, Source{Address: "100.64.0.12", PublicAddress: "8.8.8.8", TCPOnly: true})
	p.ClientListeners = []ClientListener{{ID: "shared-example", Port: 24000, Key: p.Transport.Key, Source: "8.8.4.4", Shared: true, Transport: glivela.IPv4ClientSS2022}}
	p.UDPOverTCPListeners = []string{"shared-example"}
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []any
		Routing  struct {
			Rules []struct {
				Source               []string
				Network, OutboundTag string
			}
		}
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 1 {
		t.Fatal("shared socket duplicated")
	}
	allowed := false
	for _, r := range cfg.Routing.Rules {
		if r.Network == "tcp,udp" && r.OutboundTag == "egress" {
			if len(r.Source) != 1 || r.Source[0] != "8.8.4.4/32" {
				t.Fatal("UDP widened to another source")
			}
			allowed = true
		}
	}
	if !allowed {
		t.Fatal("shared main socket lost bound UDP authorization")
	}
}
