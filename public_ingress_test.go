package glivela

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPublic443DualStackKeepsOneCredentialAndAuthorization(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	native := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(id), EntryID: "entry", Enabled: true}
	e := RealityEndpoint{ID: "endpoint", EntryID: "entry", InboundTag: "entry-in", ListenAddress: "2001:4860:4860::8888", IPv4ListenAddress: "1.1.1.1", ListenPort: 443, AdvertiseHost: "random.example.test", AdvertisePort: 443, Target: "127.0.0.1:24483", ServerNames: []string{"site.example.test"}, PrivateKey: "fixture-private", PublicKey: "fixture-public", ShortIDs: []string{"0123456789abcdef"}}
	plan := XrayPlan{Revision: 1, RealityEndpoints: []RealityEndpoint{e}, Credentials: []CredentialMaterial{{Credential: native, ProtocolID: id}}}
	raw, err := RenderXrayConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []map[string]any
		Routing  struct{ Rules []map[string]any }
	}
	if json.Unmarshal(raw, &cfg) != nil || len(cfg.Inbounds) != 3 {
		t.Fatal("missing exact dual-stack sockets")
	}
	v6, v4 := cfg.Inbounds[1], cfg.Inbounds[2]
	if v6["listen"] != e.ListenAddress || v4["listen"] != e.IPv4ListenAddress || v6["port"] != float64(443) || v4["port"] != float64(443) || !reflect.DeepEqual(v6["settings"], v4["settings"]) {
		t.Fatal("dual stack changed credentials or sockets")
	}
	for _, v := range []map[string]any{v6, v4} {
		stream := v["streamSettings"].(map[string]any)
		if stream["rawSettings"].(map[string]any)["acceptProxyProtocol"] != false {
			t.Fatal("public socket trusts spoofable PROXY header")
		}
	}
	for _, rule := range cfg.Routing.Rules {
		tags, _ := rule["inboundTag"].([]any)
		seen := map[string]bool{}
		for _, value := range tags {
			tag, _ := value.(string)
			if seen[tag] {
				t.Fatal("duplicate authorization inbound tag", tag)
			}
			seen[tag] = true
		}
		if seen[e.InboundTag] && !seen[e.InboundTag+"-ipv4"] {
			t.Fatal("IPv4 socket escaped scoped authorization")
		}
	}
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", e.ListenAddress} {
		bad := e
		bad.IPv4ListenAddress = ip
		if bad.Validate() == nil {
			t.Fatal("invalid secondary exposed", ip)
		}
	}
	bad := e
	bad.ListenPort = 24443
	if bad.Validate() == nil {
		t.Fatal("dual-stack public port was not443")
	}
}
