package meridian

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRenderLinksReplacesEntryRegionWithLandingRegion(t *testing.T) {
	baseSecret := "11111111-1111-4111-8111-111111111111"
	routeSecret := "22222222-2222-4222-8222-222222222222"
	baseLink := "vless://" + baseSecret + "@entry.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision#🇺🇸 美国｜Entry-Alpha"
	routeLink := "vless://" + routeSecret + "@entry.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision#ignored"
	grant := RouteGrant{
		ID: "grant-a", AccountID: "account-a", EntryID: "entry-a", EgressID: "egress-a", InboundTag: "vless-a",
		Base:  Credential{ID: "base-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(baseSecret), EntryID: "entry-a", Enabled: true},
		Route: Credential{ID: "route-a", AccountID: "account-a", Kind: RouteCredential, User: RouteUser("grant-a"), Identity: Identity(routeSecret), EntryID: "entry-a", EgressID: "egress-a", Enabled: true},
		Mode:  FixedMode, Enabled: true, DesiredRev: 7, AppliedRev: 7, RuntimeGood: true,
	}
	baseMaterial := CredentialMaterial{Credential: grant.Base, ProtocolID: baseSecret}
	entries := []NativeEntry{{Material: baseMaterial, Protocol: VLESSReality, Link: baseLink}}
	result, err := RenderLinks(entries, "account-a", FixedMode, []PublishedRoute{{Grant: grant, Protocol: VLESSReality, EntryName: "🇺🇸 美国｜Entry-Alpha", EgressRegionPrefix: "🇹🇼 台湾", BaseLink: baseLink, RouteLink: routeLink, BaseProtocolIdentity: grant.Base.Identity, RouteProtocolIdentity: grant.Route.Identity}}, true)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(result))
	if err != nil {
		t.Fatal(err)
	}
	text := string(decoded)
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) != 2 {
		t.Fatalf("rendered subscription = %q", text)
	}
	if native, err := parseVLESSLink(lines[0]); err != nil || native.Fragment != "🇺🇸 美国｜Entry-Alpha" {
		t.Fatalf("native subscription changed: %q", text)
	}
	routed, err := parseVLESSLink(lines[1])
	if err != nil || routed.Fragment != "🇹🇼 台湾｜双跳·Entry-Alpha" || strings.Contains(routed.Fragment, "🇺🇸") || strings.Contains(routed.Fragment, "｜｜") {
		t.Fatalf("rendered subscription = %q", text)
	}
}

func TestRenderLinksSupportsNativeOnlyAccount(t *testing.T) {
	secret := "11111111-1111-4111-8111-111111111111"
	link := "vless://" + secret + "@entry.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision#🇺🇸｜Entry-Alpha"
	credential := Credential{ID: "native-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(secret), EntryID: "entry-a", Enabled: true}
	result, err := RenderLinks([]NativeEntry{{Material: CredentialMaterial{Credential: credential, ProtocolID: secret}, Protocol: VLESSReality, Link: link}}, "account-a", FixedMode, nil, false)
	if err != nil || string(result) != link+"\n" {
		t.Fatalf("native subscription = %q, err=%v", string(result), err)
	}
}

func TestRenderLinksSkipsUnappliedRouteWithoutBreakingNativeSubscription(t *testing.T) {
	secret := "11111111-1111-4111-8111-111111111111"
	routeSecret := "22222222-2222-4222-8222-222222222222"
	link := "vless://" + secret + "@entry.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=public&sid=abcd&fp=chrome&flow=xtls-rprx-vision#🇺🇸｜Entry-Alpha"
	base := Credential{ID: "native-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(secret), EntryID: "entry-a", Enabled: true}
	grant := RouteGrant{
		ID: "grant-a", AccountID: "account-a", EntryID: "entry-a", EgressID: "egress-a", InboundTag: "vless-a",
		Base:  base,
		Route: Credential{ID: "route-a", AccountID: "account-a", Kind: RouteCredential, User: RouteUser("grant-a"), Identity: Identity(routeSecret), EntryID: "entry-a", EgressID: "egress-a", Enabled: true},
		Mode:  FixedMode, Enabled: true, DesiredRev: 2, AppliedRev: 1,
	}
	result, err := RenderLinks([]NativeEntry{{Material: CredentialMaterial{Credential: base, ProtocolID: secret}, Protocol: VLESSReality, Link: link}}, "account-a", FixedMode, []PublishedRoute{{Grant: grant, Protocol: VLESSReality, EntryName: "Entry-Alpha", BaseProtocolIdentity: base.Identity, RouteProtocolIdentity: grant.Route.Identity}}, false)
	if err != nil || string(result) != link+"\n" {
		t.Fatalf("unapplied route result = %q, err=%v", string(result), err)
	}
}

func TestRenderSubscriptionsRejectRoutedHysteria(t *testing.T) {
	baseSecret := "11111111-1111-4111-8111-111111111111"
	routeSecret := "22222222-2222-4222-8222-222222222222"
	base := Credential{ID: "native-a", AccountID: "account-a", Kind: NativeCredential, User: "Phone", Identity: Identity(baseSecret), EntryID: "entry", Enabled: true}
	route := Credential{ID: "route-a", AccountID: "account-a", Kind: RouteCredential, User: RouteUser("grant-a"), Identity: Identity(routeSecret), EntryID: "entry", EgressID: "egress-a", Enabled: true}
	baseMaterial := CredentialMaterial{Credential: base, ProtocolID: baseSecret, HysteriaAuth: "base-hy2", HysteriaIdentity: Identity("base-hy2")}
	endpoint := testHysteriaEndpoint(t)
	baseLink, err := Hysteria2LinkForCredential(endpoint, baseMaterial, "🇺🇸｜Entry · HY2")
	if err != nil {
		t.Fatal(err)
	}
	grant := RouteGrant{ID: "grant-a", AccountID: "account-a", EntryID: "entry", EgressID: "egress-a", InboundTag: "meridian-entry", Base: base, Route: route, Mode: FixedMode, Enabled: true, DesiredRev: 2, AppliedRev: 2, RuntimeGood: true}
	routes := []PublishedRoute{{Grant: grant, Protocol: Hysteria2, EntryName: "｜Entry", EgressRegionPrefix: "🇹🇼 台湾", BaseLink: baseLink, RouteLink: baseLink, BaseProtocolIdentity: baseMaterial.HysteriaIdentity, RouteProtocolIdentity: baseMaterial.HysteriaIdentity}}
	entries := []NativeEntry{{Material: baseMaterial, Protocol: Hysteria2, Link: baseLink}}
	if _, err := RenderLinks(entries, "account-a", FixedMode, routes, false); err == nil {
		t.Fatal("routed Hysteria link subscription was accepted")
	}
	if _, err := RenderMihomo(entries, "account-a", FixedMode, routes); err == nil {
		t.Fatal("routed Hysteria Mihomo subscription was accepted")
	}
}

func TestRouteNameLandingSuffix(t *testing.T) {
	for _, suffix := range []string{"", "家宽", "双跳"} {
		item := PublishedRoute{EntryName: "🇺🇸 美国｜Entry", EgressRegionPrefix: "🇺🇸 美国", EgressNameSuffix: suffix}
		want := "🇺🇸 美国｜双跳·Entry"
		if suffix != "" {
			want = "🇺🇸 美国｜" + suffix + "·Entry"
		}
		if got := routeName(item); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestCompactSubscriptionNames(t *testing.T) {
	cases := []struct{ entry, native, routed string }{
		{"DataWave-CN2", "DW-CN2", "DW-CN2"},
		{"ShanDun-CN2", "SD-CN2", "SD-CN2"},
		{"CN2 FXTRANSIT", "FX-CN2", "FX-CN2"},
		{"AKKO-CN2", "AKKO-CN2", "AKKO-CN2"},
		{"MatrixIDC CN2-1", "MX-CN2①", "MX-CN2①"},
		{"MatrixIDC CN2-2", "MX-CN2②", "MX-CN2②"},
		{"MatrixIDC 4837-1", "MX-4837①", "MX-4837①"},
		{"MatrixIDC 4837-2", "MX-4837②", "MX-4837②"},
	}
	seen := map[string]bool{}
	reserve := func(name string) {
		t.Helper()
		if seen[name] {
			t.Fatalf("duplicate display name: %s", name)
		}
		seen[name] = true
	}
	for _, tc := range cases {
		original := "🇺🇸 美国｜" + tc.entry
		got := compactSubscriptionName(original)
		if got != "🇺🇸 美国｜"+tc.native {
			t.Fatalf("native name: %s", got)
		}
		reserve(got)
		for _, landing := range []struct{ region, suffix string }{
			{"🇺🇸 美国", "家宽"}, {"🇺🇸 美国", "双跳"},
			{"🇨🇳 台湾", ""}, {"🇭🇰 香港", ""},
		} {
			got = routeName(PublishedRoute{EntryName: original, EgressRegionPrefix: landing.region, EgressNameSuffix: landing.suffix})
			want := landing.region + "｜"
			if landing.suffix != "" {
				want += landing.suffix + "·" + tc.routed
			} else {
				want += "双跳·" + tc.routed
			}
			if got != want {
				t.Fatalf("routed name: got %s, want %s", got, want)
			}
			reserve(got)
		}
	}
	reserve(compactSubscriptionName("🇺🇸 美国｜VMISS-CN2"))
	if len(seen) != 41 {
		t.Fatalf("inventory size: %d", len(seen))
	}
	unknown := "🇺🇸 美国｜Custom-CN2-9"
	if compactSubscriptionName(unknown) != unknown {
		t.Fatal("custom name was changed")
	}
}
