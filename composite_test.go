package glivela

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func compositePlanFixture() XrayPlan {
	baseID, routeID := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	base := Credential{ID: "base", AccountID: "account", Kind: NativeCredential, User: "native", Identity: Identity(baseID), EntryID: "entry", Enabled: true}
	route := Credential{ID: "route", AccountID: "account", Kind: RouteCredential, User: "routed", Identity: Identity(routeID), EntryID: "entry", EgressID: "exit6", Enabled: true}
	return XrayPlan{Revision: 2,
		RealityEndpoints: []RealityEndpoint{{ID: "endpoint", EntryID: "entry", InboundTag: "entry-in", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443, Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "fixture-private", PublicKey: "fixture-public", ShortIDs: []string{"0123456789abcdef"}}},
		Credentials:      []CredentialMaterial{{Credential: base, ProtocolID: baseID}, {Credential: route, ProtocolID: routeID}},
		Grants:           []RouteGrant{{ID: "combo", AccountID: "account", EntryID: "entry", EgressID: "exit6", IPv4EgressID: "exit4", InboundTag: "entry-in", Base: base, Route: route, Mode: FixedMode, Enabled: true, DesiredRev: 2, AppliedRev: 2, RuntimeGood: true}},
		Peers:            []RoutePeer{{EgressID: "exit6", Address: "100.64.0.6", Port: 1080, ExitFamily: EgressIPv6Only, Ready: true}, {EgressID: "exit4", Address: "100.64.0.4", Port: 1080, ExitFamily: EgressIPv4Only, Ready: true}},
	}
}

func TestCompositeBlockedNetworks(t *testing.T) {
	blocked := func(value string) bool {
		address := netip.MustParseAddr(value).Unmap()
		return slices.ContainsFunc(compositeBlockedCIDRs, func(cidr string) bool { return netip.MustParsePrefix(cidr).Contains(address) })
	}
	for _, address := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if blocked(address) || !CompositePublicIP(netip.MustParseAddr(address)) {
			t.Fatalf("public target blocked: %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "100.64.0.1", "169.254.169.254", "10.0.0.1", "192.168.0.1", "198.18.0.1", "2001:db8::1", "::1", "fd00::1", "::ffff:127.0.0.1"} {
		if !blocked(address) || CompositePublicIP(netip.MustParseAddr(address)) {
			t.Fatalf("unsafe literal accepted: %s", address)
		}
	}
	if CompositePublicIP(netip.Addr{}) || CompositePublicIP(netip.MustParseAddr("2606:4700:4700::1111%zone")) {
		t.Fatal("invalid or scoped exit address accepted")
	}
}

func TestCompositeArtifactIsDeterministicAndFailClosed(t *testing.T) {
	plan := compositePlanFixture()
	artifact, err := BuildDesiredArtifact(plan)
	if err != nil || artifact.Validate() != nil {
		t.Fatalf("artifact: %v", err)
	}
	slices.Reverse(plan.Peers)
	slices.Reverse(plan.Credentials)
	repeated, err := BuildDesiredArtifact(plan)
	if err != nil || !bytes.Equal(artifact.Config, repeated.Config) || artifact.ConfigSHA256 != repeated.ConfigSHA256 {
		t.Fatal("projection depends on input order")
	}
	var config struct {
		Outbounds []struct{ Tag, Protocol, TargetStrategy string }
		Routing   struct {
			Script, DomainStrategy string
			Rules                  []struct {
				Type, Network, OutboundTag, Port string
				InboundTag, User, IP             []string
			}
		}
		DNS struct {
			Script, QueryStrategy string
			Servers               []string
		}
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config.Outbounds[0].Protocol != "freedom" || config.Routing.Script != "" || config.DNS.Script != "" || config.Routing.DomainStrategy != "IPOnDemand" {
		t.Fatal("composite must use official routing without changing the native outbound")
	}
	if config.DNS.QueryStrategy != "UseIP" || !slices.Equal(config.DNS.Servers, []string{"https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"}) {
		t.Fatal("composite must query both address families through official local DoH")
	}
	loops, socks := 0, 0
	for _, out := range config.Outbounds {
		if out.Protocol == "loopback" {
			loops++
		}
		if out.Protocol == "socks" {
			socks++
			want := "ForceIPv6"
			if strings.HasSuffix(out.Tag, "-ipv4") {
				want = "ForceIPv4"
			}
			if out.TargetStrategy != want {
				t.Fatal("SOCKS destination family is not forced")
			}
		}
	}
	if loops != 0 || socks != 2 {
		t.Fatal("composite must select one outbound without redispatch or duplicate user accounting")
	}
	if len(config.Routing.Rules) != 9 {
		t.Fatal("missing composite rules")
	}
	rules := config.Routing.Rules[3:]
	for _, rule := range rules[:5] {
		if rule.Type != "field" || !slices.Equal(rule.InboundTag, []string{"entry-in"}) || !slices.Equal(rule.User, []string{"routed"}) {
			t.Fatal("route authority boundary absent")
		}
	}
	if rules[0].Network != "udp" || rules[0].OutboundTag != "blocked" || rules[1].Network != "tcp" || rules[1].OutboundTag != "blocked" || !strings.Contains(","+rules[1].Port+",", ",22,") || rules[2].OutboundTag != "blocked" || !slices.Equal(rules[2].IP, compositeBlockedCIDRs) {
		t.Fatal("unsafe targets must be blocked before family selection")
	}
	if !slices.Equal(rules[3].IP, []string{"::/0"}) || rules[3].OutboundTag != routeOutboundTag("combo") || !slices.Equal(rules[4].IP, []string{"0.0.0.0/0"}) || rules[4].OutboundTag != routeOutboundTag("combo")+"-ipv4" {
		t.Fatal("IPv6 must precede IPv4")
	}
	if rules[5].OutboundTag != "blocked" || len(rules[5].InboundTag) != 0 || !slices.Equal(rules[5].User, []string{"routed"}) {
		t.Fatal("unresolved or incorrectly scoped credentials can fall through")
	}
	changed := artifact
	changed.Config = append(bytes.Clone(artifact.Config), ' ')
	if changed.Validate() == nil {
		t.Fatal("configuration mutation accepted")
	}
	for _, section := range []string{"routing", "dns"} {
		var candidate map[string]any
		if err := json.Unmarshal(artifact.Config, &candidate); err != nil {
			t.Fatal(err)
		}
		candidate[section].(map[string]any)["script"] = "/etc/vastora/obsolete.lua"
		changed.Config, err = json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(changed.Config)
		changed.ConfigSHA256 = hex.EncodeToString(digest[:])
		if changed.Validate() == nil {
			t.Fatal("custom script artifact accepted")
		}
	}
}

func TestCompositePreservesNativeAndFixedRoutes(t *testing.T) {
	plan := compositePlanFixture()
	fixed := plan.Grants[0]
	fixed.ID, fixed.IPv4EgressID, fixed.Route.ID, fixed.Route.User = "fixed", "", "fixed-credential", "fixed-user"
	fixedProtocol := "00000000-0000-4000-8000-000000000003"
	fixed.Route.Identity = Identity(fixedProtocol)
	plan.Grants = append(plan.Grants, fixed)
	plan.Credentials = append(plan.Credentials, CredentialMaterial{Credential: fixed.Route, ProtocolID: fixedProtocol})
	encoded, err := RenderXrayConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag      string
			Sniffing struct {
				Enabled, RouteOnly bool
				DestOverride       []string
			}
			Settings struct{ Clients []struct{ Email string } }
		}
		Outbounds []struct{ Tag, Protocol, TargetStrategy string }
		Routing   struct {
			Rules []struct {
				User, IP             []string
				Network, OutboundTag string
			}
		}
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "entry-in" && (!inbound.Sniffing.Enabled || inbound.Sniffing.RouteOnly || len(inbound.Settings.Clients) != 3 || !slices.Equal(inbound.Sniffing.DestOverride, []string{"http", "tls"})) {
			t.Fatal("native credentials or existing hostname sniffing changed")
		}
	}
	for _, outbound := range config.Outbounds {
		if outbound.Tag == routeOutboundTag("fixed") && (outbound.Protocol != "socks" || outbound.TargetStrategy != "") {
			t.Fatal("fixed exit acquired composite resolution")
		}
	}
	fixedRules := 0
	for _, rule := range config.Routing.Rules {
		if !slices.Equal(rule.User, []string{"fixed-user"}) {
			continue
		}
		fixedRules++
		if len(rule.IP) != 0 {
			t.Fatal("fixed route acquired a family rule")
		}
		if rule.Network == "tcp" && rule.OutboundTag != routeOutboundTag("fixed") {
			t.Fatal("fixed TCP route changed")
		}
	}
	if fixedRules != 3 {
		t.Fatal("fixed routing boundary changed")
	}
}

func TestWithoutCompositeUsesBusinessDNSWithoutCompositeSelection(t *testing.T) {
	plan := compositePlanFixture()
	plan.Grants[0].IPv4EgressID = ""
	plan.Peers = plan.Peers[:1]
	encoded, err := RenderXrayConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		DNS     json.RawMessage
		Routing struct {
			DomainStrategy string
			Rules          []json.RawMessage
		}
		Outbounds []struct{ Protocol, TargetStrategy string }
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.DNS) == 0 || config.Routing.DomainStrategy != "IPIfNonMatch" || len(config.Routing.Rules) != 6 || len(config.Outbounds) != 4 || config.Outbounds[0].Protocol != "freedom" || config.Outbounds[2].Protocol != "socks" || config.Outbounds[2].TargetStrategy != "" {
		t.Fatal("single-exit configuration acquired composite DNS or family selection")
	}
	var dns struct {
		Tag, QueryStrategy string
		Servers            []string
	}
	if json.Unmarshal(config.DNS, &dns) != nil || dns.Tag != "resolver" || !slices.Equal(dns.Servers, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Fatal("single-exit business DNS was not isolated")
	}
}

func TestCompositeRequiresTwoReadyIndependentStrictExits(t *testing.T) {
	for _, change := range []func(*XrayPlan){
		func(p *XrayPlan) { p.Peers[1].Ready = false },
		func(p *XrayPlan) { p.Peers[0].ExitFamily = EgressAuto },
		func(p *XrayPlan) { p.Peers[1].ExitFamily = EgressIPv6Only },
		func(p *XrayPlan) { p.Peers[1].Address = p.Peers[0].Address },
		func(p *XrayPlan) { p.Peers[0].Address = p.RealityEndpoints[0].ListenAddress },
		func(p *XrayPlan) { p.Peers[1].Address = p.RealityEndpoints[0].ListenAddress },
		func(p *XrayPlan) { p.Grants[0].IPv4EgressID = p.Grants[0].EntryID },
		func(p *XrayPlan) { p.Peers = p.Peers[:1] },
	} {
		plan := compositePlanFixture()
		change(&plan)
		if _, err := BuildDesiredArtifact(plan); err == nil {
			t.Fatal("incomplete composite authority accepted")
		}
	}
}

func TestCompositeSubscriptionIsOneStableIdentityAndOneQuotaMember(t *testing.T) {
	plan := compositePlanFixture()
	grant := plan.Grants[0]
	base, err := LinkForCredential(plan.RealityEndpoints[0], plan.Credentials[0], "Entry")
	if err != nil {
		t.Fatal(err)
	}
	routed, err := LinkForCredential(plan.RealityEndpoints[0], plan.Credentials[1], "Entry")
	if err != nil {
		t.Fatal(err)
	}
	entries := []NativeEntry{{Material: plan.Credentials[0], Protocol: VLESSReality, Link: base}}
	publication := PublishedRoute{Grant: grant, Protocol: VLESSReality, EntryName: "Entry", BaseLink: base, RouteLink: routed, BaseProtocolIdentity: grant.Base.Identity, RouteProtocolIdentity: grant.Route.Identity}
	links, err := RenderLinks(entries, "account", FixedMode, []PublishedRoute{publication}, false)
	if err != nil || len(strings.Split(strings.TrimSpace(string(links)), "\n")) != 2 {
		t.Fatalf("one native plus one composite required: %v", err)
	}
	if !strings.Contains(string(links), "IPv6优先+IPv4") || strings.Count(string(links), plan.Credentials[1].ProtocolID) != 1 {
		t.Fatal("composite split into multiple client identities")
	}
	if _, err := RenderMihomo(entries, "account", FixedMode, []PublishedRoute{publication}); err != nil {
		t.Fatal(err)
	}
	quota, err := ProjectQuota(AccountPlan{Enabled: true, TotalBytes: 1000}, []UsageMember{{CredentialID: grant.Base.ID, Observed: 100, Active: true}, {CredentialID: grant.Route.ID, Observed: 200, Active: true}})
	if err != nil || quota.UsedBytes != 300 {
		t.Fatalf("shared quota=%+v err=%v", quota, err)
	}
}

func TestCompositeNamesDistinguishBothExitRegionsAndRepeatedPairs(t *testing.T) {
	first := PublishedRoute{Grant: RouteGrant{ID: "a", IPv4EgressID: "four-a"}, EntryName: "Entry", EgressRegionPrefix: "🇺🇸", IPv4EgressRegionPrefix: "🇭🇰"}
	second := first
	second.Grant.ID, second.Grant.IPv4EgressID = "b", "four-b"
	labels := compositeRouteLabels([]PublishedRoute{second, first})
	if labels["a"] == labels["b"] || !strings.HasSuffix(labels["a"], "①") || !strings.HasSuffix(labels["b"], "②") || !strings.Contains(labels["a"], "🇺🇸 + 🇭🇰") {
		t.Fatal("ambiguous or misleading composite names")
	}
	if routeName(first) != strings.TrimSuffix(labels["a"], "①") {
		t.Fatal("a single combination should not have a sequence suffix")
	}
}

func TestCompositePreservesNamedSingleExitSubscription(t *testing.T) {
	plan := compositePlanFixture()
	grant := plan.Grants[0]
	base, err := LinkForCredential(plan.RealityEndpoints[0], plan.Credentials[0], "🇺🇸 美国｜AKKO-CN2")
	if err != nil {
		t.Fatal(err)
	}
	routed, err := LinkForCredential(plan.RealityEndpoints[0], plan.Credentials[1], "ignored")
	if err != nil {
		t.Fatal(err)
	}
	publication := PublishedRoute{
		Grant: grant, Protocol: VLESSReality, EntryName: "🇺🇸 美国｜AKKO-CN2",
		EgressNameSuffix: "家宽", EgressRegionPrefix: "🇺🇸 美国", IPv4EgressRegionPrefix: "🇺🇸 美国",
		BaseLink: base, RouteLink: routed, BaseProtocolIdentity: grant.Base.Identity, RouteProtocolIdentity: grant.Route.Identity,
	}
	want := "🇺🇸 美国｜家宽·AKKO-CN2"
	single := publication
	single.Grant.IPv4EgressID = ""
	if routeName(single) != want || routeName(publication) != want {
		t.Fatal("adding an IPv4 exit changed the configured home route name")
	}
	entries := []NativeEntry{{Material: plan.Credentials[0], Protocol: VLESSReality, Link: base}}
	links, err := RenderLinks(entries, "account", FixedMode, []PublishedRoute{publication}, false)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(links)), "\n")
	if len(lines) != 2 {
		t.Fatal("converted home route must remain one subscription entry")
	}
	link, err := parseVLESSLink(lines[1])
	if err != nil || link.Fragment != want || link.User.Username() != plan.Credentials[1].ProtocolID {
		t.Fatal("converted home route name or credential changed")
	}
	mihomo, err := RenderMihomo(entries, "account", FixedMode, []PublishedRoute{publication})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Proxies []struct {
			Name string `yaml:"name"`
			UUID string `yaml:"uuid"`
		}
	}
	if err := yaml.Unmarshal(mihomo, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Proxies) != 2 || config.Proxies[1].Name != want || config.Proxies[1].UUID != plan.Credentials[1].ProtocolID {
		t.Fatal("Mihomo converted home route name or credential changed")
	}
}

func TestCompositeNamedRouteCoexistsWithExistingSingleExit(t *testing.T) {
	single := PublishedRoute{Grant: RouteGrant{ID: "home"}, EntryName: "AKKO-CN2", EgressNameSuffix: "家宽", EgressRegionPrefix: "🇺🇸 美国"}
	combo := single
	combo.Grant.ID, combo.Grant.IPv4EgressID = "test", "four"
	combo.IPv4EgressRegionPrefix = "🇺🇸 美国"
	labels := compositeRouteLabels([]PublishedRoute{single, combo})
	if labels["test"] != routeName(single)+"①" || labels["home"] != "" {
		t.Fatal("composite test route must not collide with or rename an existing home route")
	}
}
