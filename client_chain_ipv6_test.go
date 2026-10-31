package glivela

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIPv6ClientChainSubscription(t *testing.T) {
	secret := "11111111-1111-4111-8111-111111111111"
	base := Credential{ID: "native-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(secret), EntryID: "entry-a", Enabled: true}
	entry := NativeEntry{Material: CredentialMaterial{Credential: base, ProtocolID: secret}, Protocol: VLESSReality, Link: "vless://" + secret + "@entry.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision#Entry"}
	chain := ClientChain{ID: "chain-a", AccountID: "account-a", EntryID: "entry-a", EgressID: "egress-a", Name: "HK V6 → BGP", Port: 24001, Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Enabled: true, Transport: "ipv6-ss2022", SourceIPv6: "2001:4860:4860::8888", ServerIPv6: "2606:4700:4700::1111", EntryCertificateID: strings.Repeat("a", 64), LandingCertificateID: strings.Repeat("b", 64)}
	publication := PublishedClientChain{Chain: chain, Base: entry, Server: chain.ServerIPv6}
	before, err := RenderMihomo([]NativeEntry{entry}, "account-a", FixedMode, nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := RenderMihomo([]NativeEntry{entry}, "account-a", FixedMode, nil, publication)
	if err != nil {
		t.Fatal(err)
	}
	var old, result struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(before, &old) != nil || yaml.Unmarshal(output, &result) != nil {
		t.Fatal("subscription could not be parsed")
	}
	if len(old.Proxies) != 1 || len(result.Proxies) != 3 || result.Proxies[0]["name"] != old.Proxies[0]["name"] || result.Proxies[0]["uuid"] != old.Proxies[0]["uuid"] {
		t.Fatal("existing native entry changed")
	}
	var transport, dependency map[string]any
	for _, proxy := range result.Proxies {
		if proxy["type"] == "ss" {
			transport = proxy
		}
	}
	for _, proxy := range result.Proxies {
		if transport != nil && proxy["name"] == transport["dialer-proxy"] {
			dependency = proxy
		}
	}
	if transport == nil || transport["name"] != chain.Name || dependency == nil || dependency["type"] != "vless" || dependency["uuid"] != secret || transport["server"] != chain.ServerIPv6 || transport["cipher"] != SS2022Method || transport["password"] != chain.Key || transport["udp"] != false {
		t.Fatal("chain lost its IPv6 SS2022 target, TCP policy or VLESS dependency")
	}
	second := chain
	second.ID, second.EgressID, second.Name, second.Port, second.ServerIPv6 = "chain-b", "egress-b", "Entry IPv6 → Landing IPv6", 24002, "2606:4700:4700::1001"
	second.LandingCertificateID = strings.Repeat("c", 64)
	two, err := RenderMihomo([]NativeEntry{entry}, "account-a", FixedMode, nil, publication, PublishedClientChain{Chain: second, Base: entry, Server: second.ServerIPv6})
	if err != nil || yaml.Unmarshal(two, &result) != nil {
		t.Fatal("two landing chains could not be rendered")
	}
	seen := map[string]bool{}
	for _, proxy := range result.Proxies {
		if proxy["type"] == "ss" {
			seen[proxy["name"].(string)] = true
			if proxy["dialer-proxy"] != dependency["name"] {
				t.Fatal("landing chains lost their shared VLESS dependency")
			}
		}
	}
	if !seen[chain.Name] || !seen[second.Name] || len(seen) != 2 {
		t.Fatal("landing names are missing or ambiguous")
	}
	publication.Server = "1.1.1.1"
	if _, err := RenderMihomo([]NativeEntry{entry}, "account-a", FixedMode, nil, publication); err == nil {
		t.Fatal("unexpected server allowed an IPv4 fallback")
	}
	if _, err := RenderMihomo([]NativeEntry{entry}, "other-account", FixedMode, nil, PublishedClientChain{Chain: chain, Base: entry, Server: chain.ServerIPv6}); err == nil {
		t.Fatal("another account received the chain")
	}
	for _, mutate := range []func(*ClientChain){
		func(c *ClientChain) { c.SourceIPv6 = "::/0" },
		func(c *ClientChain) { c.SourceIPv6 = "fd00::1" },
		func(c *ClientChain) { c.ServerIPv6 = "::" },
		func(c *ClientChain) { c.LandingCertificateID = c.EntryCertificateID },
		func(c *ClientChain) { c.Key = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
	} {
		invalid := chain
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatal("invalid source, endpoint, identity or key accepted")
		}
	}
}
