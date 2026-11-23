package glivela

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRetiredClientChainValidationAndSubscriptionsRejectDialerProxy(t *testing.T) {
	secret := "11111111-1111-4111-8111-111111111111"
	base := Credential{ID: "native-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(secret), EntryID: "entry-a", Enabled: true}
	entry := NativeEntry{Material: CredentialMaterial{Credential: base, ProtocolID: secret}, Protocol: VLESSReality, Link: "vless://" + secret + "@entry.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision#Entry"}
	output, items, err := RenderMihomo([]NativeEntry{entry}, "account-a", FixedMode, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "dialer-proxy") || len(items) != 1 || items[0].Kind != "native" {
		t.Fatalf("unexpected Mihomo output: %s", output)
	}
	var result struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(output, &result) != nil || len(result.Proxies) != 1 || result.Proxies[0]["type"] != "vless" {
		t.Fatal("rendered Mihomo inventory changed")
	}
	// Shadowrocket renderer must reject retired client-chain Shadowsocks or dialer-proxy proxies.
	for _, retiredYAML := range []string{
		"proxies:\n  - name: Helper\n    type: vless\n    server: entry.example.com\n    port: 443\n    uuid: " + secret + "\n    network: tcp\n    servername: www.example.com\n    flow: xtls-rprx-vision\n    reality-opts:\n      public-key: public\n      short-id: abcd\n  - name: Chain\n    type: ss\n    server: 2606:4700:4700::1111\n    port: 24001\n    cipher: " + SS2022Method + "\n    password: " + base64.StdEncoding.EncodeToString(make([]byte, 16)) + "\n    dialer-proxy: Helper\n",
		"proxies:\n  - name: ChainedVLESS\n    type: vless\n    server: entry.example.com\n    port: 443\n    uuid: " + secret + "\n    network: tcp\n    servername: www.example.com\n    flow: xtls-rprx-vision\n    dialer-proxy: Helper\n    reality-opts:\n      public-key: public\n      short-id: abcd\n",
	} {
		if _, err := RenderShadowrocketNodes([]byte(retiredYAML)); err == nil {
			t.Fatal("retired client-chain proxy accepted by Shadowrocket renderer")
		}
	}
	// Legacy ClientChain records remain strictly validated for historical ledger compatibility.
	chain := ClientChain{ID: "chain-a", AccountID: "account-a", EntryID: "entry-a", EgressID: "egress-a", Name: "Entry IPv6 → Landing IPv6", Port: 24001, Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Enabled: false, Transport: "ipv6-ss2022", SourceIPv6: "2001:4860:4860::8888", ServerIPv6: "2606:4700:4700::1111", EntryCertificateID: strings.Repeat("a", 64), LandingCertificateID: strings.Repeat("b", 64)}
	if err := chain.Validate(); err != nil {
		t.Fatal("valid historical ClientChain rejected:", err)
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
			t.Fatal("invalid historical source, endpoint, identity or key accepted")
		}
	}
}
