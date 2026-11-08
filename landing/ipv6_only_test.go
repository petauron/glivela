package landing

import (
	"encoding/base64"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"reflect"
	"strings"
	"testing"
)

func TestIPv6OnlyLandingRetainsButNeverActivatesIPv4(t *testing.T) {
	p := fixturePlan()
	p.EgressIP = "2606:4700::100"
	p.Sources = []Source{{Address: "100.64.0.11", PublicAddress: "1.1.1.1", TCPOnly: true}}
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	p.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: "9.9.9.9"}
	p.ClientListeners = []ClientListener{
		{ID: "old", Shared: true, Transport: glivela.IPv4ClientSS2022, Port: 24000, Key: key, Source: "1.1.1.1"},
		{ID: "new", Shared: true, Transport: "ipv6-ss2022", Port: 24000, Key: key, Source: "2001:4860:4860::8888", Address: "2606:4700:4700::1111"},
	}
	old, err := p.RenderVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	current, err := p.Render()
	if err != nil || string(current) != string(old) {
		t.Fatal("ordinary released render changed", err)
	}
	original := p
	p.IPv6OnlyAddress = p.ClientListeners[1].Address
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport != original.Transport || !reflect.DeepEqual(p.Sources, original.Sources) || !reflect.DeepEqual(p.ClientListeners, original.ClientListeners) {
		t.Fatal("retained identities changed")
	}
	var config struct {
		Inbounds []struct {
			Listen   string
			Port     int
			Protocol string
		}
		DNS struct{ Servers []string }
	}
	if json.Unmarshal(raw, &config) != nil || len(config.Inbounds) != 1 || config.Inbounds[0].Listen != p.IPv6OnlyAddress || config.Inbounds[0].Port != 24000 || config.Inbounds[0].Protocol != "shadowsocks" {
		t.Fatal("IPv4/base listener was activated")
	}
	if strings.Contains(string(raw), "9.9.9.9") || strings.Contains(string(raw), "1.1.1.1") || !reflect.DeepEqual(config.DNS.Servers, []string{"tcp://[2606:4700:4700::1111]", "tcp://[2606:4700:4700::1001]"}) {
		t.Fatal("IPv4 traffic or resolver fallback")
	}
	policy, err := p.Firewall(990, "eth0")
	if err != nil || !policy.IPv6Only || policy.Address != p.IPv6OnlyAddress || len(policy.Sources) != 0 || len(policy.ClientListeners) != 1 {
		t.Fatal("firewall did not narrow to IPv6", err)
	}
	objects, _ := json.Marshal(policy.objects())
	if strings.Contains(string(objects), "9.9.9.9") || strings.Contains(string(objects), "1.1.1.1") || !strings.Contains(string(objects), p.ClientListeners[1].Source) {
		t.Fatal("firewall widened retained sources")
	}
	for _, version := range []uint8{0, 1, 2} {
		if _, err := p.RenderVersion(version); err == nil {
			t.Fatal("old program accepted IPv6-only format")
		}
	}
	for _, address := range []string{"::", "fd00::1", "1.1.1.1", "2606:4700:4700::1001"} {
		bad := p
		bad.IPv6OnlyAddress = address
		if bad.Validate() == nil {
			t.Fatal("invalid or mismatched bind accepted", address)
		}
	}
	p.Transport = glivela.PrivateTransport{}
	p.Sources = nil
	p.ClientListeners = p.ClientListeners[1:]
	if _, err := p.Render(); err != nil {
		t.Fatal("new pure IPv6 landing still requires an IPv4", err)
	}
}
