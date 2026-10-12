package meridian

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
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

func TestCompositeSelectionMatrix(t *testing.T) {
	ip6, ip4 := netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("1.1.1.1")
	for _, test := range []struct {
		name, target string
		six, four    FamilyAnswer
		family       EgressPolicy
		fail         bool
	}{
		{"IPv6 only", "www.example.com", FamilyAnswer{DNSSuccess, []netip.Addr{ip6}}, FamilyAnswer{DNSNoData, nil}, EgressIPv6Only, false},
		{"dual stack", "www.example.com", FamilyAnswer{DNSSuccess, []netip.Addr{ip6}}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, EgressIPv6Only, false},
		{"A only", "www.example.com", FamilyAnswer{DNSNoData, nil}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, EgressIPv4Only, false},
		{"AAAA failure with A", "www.example.com", FamilyAnswer{DNSFailure, nil}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, "", true},
		{"AAAA timeout with A", "www.example.com", FamilyAnswer{DNSTimeout, nil}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, "", true},
		{"NXDOMAIN", "www.example.com", FamilyAnswer{DNSNotFound, nil}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, "", true},
		{"empty success", "www.example.com", FamilyAnswer{DNSSuccess, nil}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, "", true},
		{"no address", "www.example.com", FamilyAnswer{DNSNoData, nil}, FamilyAnswer{DNSNoData, nil}, "", true},
		{"false NODATA", "www.example.com", FamilyAnswer{DNSNoData, []netip.Addr{ip6}}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, "", true},
		{"blocked AAAA with A", "www.example.com", FamilyAnswer{DNSSuccess, []netip.Addr{netip.MustParseAddr("fd00::1")}}, FamilyAnswer{DNSSuccess, []netip.Addr{ip4}}, "", true},
		{"IPv4 literal", "1.1.1.1", FamilyAnswer{}, FamilyAnswer{}, EgressIPv4Only, false},
		{"IPv6 literal", ip6.String(), FamilyAnswer{}, FamilyAnswer{}, EgressIPv6Only, false},
		{"raw Fake IP", "198.18.0.1", FamilyAnswer{}, FamilyAnswer{}, "", true},
		{"missing hostname", "", FamilyAnswer{}, FamilyAnswer{}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected, err := SelectCompositeDestination(test.target, 443, test.six, test.four)
			if (err != nil) != test.fail || !test.fail && selected.Family != test.family {
				t.Fatalf("selection=%+v error=%v", selected, err)
			}
		})
	}
	for _, address := range []string{"127.0.0.1", "100.64.0.1", "169.254.169.254", "10.0.0.1", "192.168.0.1", "2001:db8::1", "::1", "::ffff:127.0.0.1", "2606:4700:4700::1111%zone"} {
		if _, err := SelectCompositeDestination(address, 443, FamilyAnswer{}, FamilyAnswer{}); err == nil {
			t.Fatalf("unsafe literal accepted: %s", address)
		}
	}
	if _, err := SelectCompositeDestination("www.example.com", 22, FamilyAnswer{DNSSuccess, []netip.Addr{ip6}}, FamilyAnswer{}); err == nil {
		t.Fatal("management port accepted")
	}
}

func TestCompositeArtifactIsDeterministicAndFailClosed(t *testing.T) {
	plan := compositePlanFixture()
	artifact, err := BuildDesiredArtifact(plan)
	if err != nil || artifact.Validate() != nil || len(artifact.Files) != 1 {
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
			Script string
			Rules  []any
		}
		DNS struct {
			Script  string
			Servers []struct {
				ID           string
				SkipFallback bool
			}
		}
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config.Outbounds[0].Protocol != "blackhole" || config.Routing.Script == "" || config.DNS.Script != "" || len(config.Routing.Rules) != 0 {
		t.Fatal("script failure can escape through ordinary routing")
	}
	if len(config.DNS.Servers) != 2 || config.DNS.Servers[0].ID != "native" || config.DNS.Servers[1].ID != "composite" || !config.DNS.Servers[1].SkipFallback {
		t.Fatal("composite DNS changed native resolution")
	}
	loops, socks := 0, 0
	for _, out := range config.Outbounds {
		if out.Protocol == "loopback" {
			loops++
		}
		if out.Protocol == "socks" {
			socks++
		}
	}
	if loops != 0 || socks != 2 {
		t.Fatal("composite must pin one selected target without redispatch or duplicate user accounting")
	}
	for name, contents := range artifact.Files {
		changed := artifact
		changed.Files = map[string][]byte{}
		for key, data := range artifact.Files {
			changed.Files[key] = bytes.Clone(data)
		}
		changed.Files[name] = append(changed.Files[name], ' ')
		if changed.Validate() == nil {
			t.Fatal("script mutation accepted")
		}
		if strings.Contains(name, "routing") && (!strings.Contains(string(contents), "tcp_only") || !strings.Contains(string(contents), "credential_scope")) {
			t.Fatal("route authority boundary absent")
		}
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
