package glivela

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResolvedSubscriptionMatchesBothFormatsAndHiddenNative(t *testing.T) {
	for _, hide := range []bool{false, true} {
		baseSecret := "11111111-1111-4111-8111-111111111111"
		routeSecret := "22222222-2222-4222-8222-222222222222"
		transport := "@entry.example.test:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision"
		base := Credential{ID: "base-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(baseSecret), EntryID: "entry-a", Enabled: true}
		grant := RouteGrant{ID: "grant-a", AccountID: "account-a", EntryID: "entry-a", EgressID: "egress-a", InboundTag: "vless-a", Base: base, Route: Credential{ID: "route-a", AccountID: "account-a", Kind: RouteCredential, User: RouteUser("grant-a"), Identity: Identity(routeSecret), EntryID: "entry-a", EgressID: "egress-a", Enabled: true}, Mode: FixedMode, Enabled: true, HideNative: hide, DesiredRev: 1, AppliedRev: 1, RuntimeGood: true}
		entries := []NativeEntry{{Material: CredentialMaterial{Credential: base, ProtocolID: baseSecret}, Protocol: VLESSReality, Link: "vless://" + baseSecret + transport + "#Entry-Alpha"}}
		routes := []PublishedRoute{{Grant: grant, Protocol: VLESSReality, EntryName: "Entry-Alpha", EgressRegionPrefix: "🇨🇳 台湾", BaseLink: entries[0].Link, RouteLink: "vless://" + routeSecret + transport + "#ignored", BaseProtocolIdentity: base.Identity, RouteProtocolIdentity: grant.Route.Identity}}
		resolved, err := resolveSubscription(entries, "account-a", FixedMode, routes)
		if err != nil {
			t.Fatal(err)
		}
		links, err := RenderLinks(entries, "account-a", FixedMode, routes, false)
		if err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(links)), "\n") {
			parsed, err := url.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, parsed.Fragment)
		}
		mihomo, err := RenderMihomo(entries, "account-a", FixedMode, routes)
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Proxies []struct {
				Name string `yaml:"name"`
				UDP  bool   `yaml:"udp"`
			} `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(mihomo, &config); err != nil {
			t.Fatal(err)
		}
		previewNames, mihomoNames := []string{}, []string{}
		for _, item := range resolved {
			previewNames = append(previewNames, item.Name)
		}
		for _, proxy := range config.Proxies {
			mihomoNames = append(mihomoNames, proxy.Name)
		}
		if !reflect.DeepEqual(names, previewNames) || !reflect.DeepEqual(names, mihomoNames) {
			t.Fatalf("different final inventories: %v %v %v", names, previewNames, mihomoNames)
		}
		want := 2
		if hide {
			want = 1
		}
		if len(resolved) != want {
			t.Fatal("HideNative disagrees with preview")
		}
		if config.Proxies[len(config.Proxies)-1].UDP {
			t.Fatal("routed TCP policy changed")
		}
	}
}

func TestResolvedCompositeIsOneSharedIdentityInBothFormats(t *testing.T) {
	for _, hide := range []bool{false, true} {
		plan := compositePlanFixture()
		grant := plan.Grants[0]
		grant.HideNative = hide
		base, err := LinkForCredential(plan.RealityEndpoints[0], plan.Credentials[0], "🇺🇸 美国｜AKKO-CN2")
		if err != nil {
			t.Fatal(err)
		}
		route, err := LinkForCredential(plan.RealityEndpoints[0], plan.Credentials[1], "ignored")
		if err != nil {
			t.Fatal(err)
		}
		entries := []NativeEntry{{Material: plan.Credentials[0], Protocol: VLESSReality, Link: base}}
		routes := []PublishedRoute{{Grant: grant, Protocol: VLESSReality, EntryName: "🇺🇸 美国｜AKKO-CN2", EgressNameSuffix: "家宽", EgressRegionPrefix: "🇺🇸 美国", IPv4EgressRegionPrefix: "🇺🇸 美国", BaseLink: base, RouteLink: route, BaseProtocolIdentity: grant.Base.Identity, RouteProtocolIdentity: grant.Route.Identity}}
		items, err := resolveSubscription(entries, "account", FixedMode, routes)
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if hide {
			want = 1
		}
		if len(items) != want {
			t.Fatal("composite was split or native duplicated", items)
		}
		links, err := RenderLinks(entries, "account", FixedMode, routes, false)
		if err != nil {
			t.Fatal(err)
		}
		mihomo, err := RenderMihomo(entries, "account", FixedMode, routes)
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Proxies []struct {
				Name string `yaml:"name"`
				UUID string `yaml:"uuid"`
				UDP  bool   `yaml:"udp"`
			} `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(mihomo, &config); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(links)), "\n")
		if len(lines) != want || len(config.Proxies) != want {
			t.Fatal("format count mismatch")
		}
		for i, item := range items {
			parsed, err := url.Parse(lines[i])
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Fragment != item.Name || config.Proxies[i].Name != item.Name || config.Proxies[i].UUID != parsed.User.Username() {
				t.Fatal("shared identity or output order diverged")
			}
		}
		routed := config.Proxies[len(config.Proxies)-1]
		if routed.UUID != plan.Credentials[1].ProtocolID || routed.UDP || routed.Name != "🇺🇸 美国｜家宽·AKKO-CN2" {
			t.Fatal("composite changed identity, TCP policy or configured name")
		}
	}
}
