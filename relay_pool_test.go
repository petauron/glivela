package glivela

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func testSS2022Key16(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 16))
}

func TestRelayPoolModelsAndValidation(t *testing.T) {
	k1 := testSS2022Key16(1)
	k2 := testSS2022Key16(2)
	eihPass := k1 + ":" + k2
	if !ValidSS2022Key16(k1) || ValidSS2022Key16(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 17))) || ValidSS2022Key16("not-base64") {
		t.Fatal("ValidSS2022Key16 accepted invalid key")
	}
	if !ValidEIHPassword(eihPass) || ValidEIHPassword(k1) || ValidEIHPassword(k1+":"+k2+":"+k1) {
		t.Fatal("ValidEIHPassword accepted malformed credential")
	}

	pt := PrivateTransport{Protocol: "ss2022", PublicAddress: "9.9.9.9", Port: RelayPoolPort, Key: eihPass}
	if err := pt.Validate(); err != nil {
		t.Fatalf("valid EIH PrivateTransport rejected: %v", err)
	}
	badPT := pt
	badPT.Port = 24001
	if badPT.Validate() == nil {
		t.Fatal("EIH PrivateTransport accepted non-24000 port")
	}
	badPT = pt
	badPT.PrivateLink = &PrivateClientLink{Source: "10.20.0.3", Address: "10.20.0.2", SourceInterface: "ens8", Interface: "ens8"}
	if badPT.Validate() == nil {
		t.Fatal("EIH PrivateTransport accepted PrivateLink")
	}

	obs := DefaultObservatoryConfig()
	if err := obs.Validate(); err != nil {
		t.Fatalf("default ObservatoryConfig rejected: %v", err)
	}
	for _, mutate := range []func(*ObservatoryConfig){
		func(c *ObservatoryConfig) { c.IntervalSec = 9 },
		func(c *ObservatoryConfig) { c.IntervalSec = 301 },
		func(c *ObservatoryConfig) { c.Sampling = 0 },
		func(c *ObservatoryConfig) { c.TimeoutSec = c.IntervalSec + 1 },
		func(c *ObservatoryConfig) { c.Destination = "ftp://example.com/probe" },
		func(c *ObservatoryConfig) { c.Destination = "https://user:pass@example.com/probe" },
		func(c *ObservatoryConfig) { c.Destination = "https://example.com/probe#frag" },
	} {
		bad := obs
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid ObservatoryConfig accepted: %+v", bad)
		}
	}

	strat := DefaultRelayPoolStrategy(2)
	if err := strat.Validate(); err != nil {
		t.Fatalf("default RelayPoolStrategy rejected: %v", err)
	}
	for _, mutate := range []func(*RelayPoolStrategy){
		func(s *RelayPoolStrategy) { s.Expected = 0 },
		func(s *RelayPoolStrategy) { s.MaxRTTMS = 49 },
		func(s *RelayPoolStrategy) { s.Tolerance = -0.1 },
		func(s *RelayPoolStrategy) { s.Tolerance = 1.1 },
		func(s *RelayPoolStrategy) { s.Tolerance = math.NaN() },
		func(s *RelayPoolStrategy) { s.Tolerance = math.Inf(1) },
	} {
		bad := strat
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid RelayPoolStrategy accepted: %+v", bad)
		}
	}

	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	member := RelayPoolMember{
		NodeID:        "relay-a",
		CertificateID: strings.Repeat("a", 64),
		IngressIPv6:   "2001:4860:4860::8888",
		EgressIPv6:    "2001:4860:4860::8888",
	}
	if err := member.Validate(); err != nil {
		t.Fatalf("valid RelayPoolMember rejected: %v", err)
	}
	if member.IsDrained(now) {
		t.Fatal("undrained member reported drained")
	}
	member.Drained = true
	member.DrainReason = "line-jitter"
	member.DrainResumeAt = now.Add(time.Hour)
	if err := member.Validate(); err != nil {
		t.Fatalf("drained member rejected: %v", err)
	}
	if !member.IsDrained(now) || member.IsDrained(now.Add(2*time.Hour)) {
		t.Fatal("DrainResumeAt boundary check failed")
	}
	member.DrainResumeAt = time.Time{}
	if !member.IsDrained(now.Add(24 * time.Hour)) {
		t.Fatal("indefinite drain should stay drained")
	}
	badMember := member
	badMember.Drained = false
	if badMember.Validate() == nil {
		t.Fatal("drain metadata accepted without Drained=true")
	}

	pool := RelayPool{
		ID:       "pool-hk",
		Name:     "HK Relay Pool",
		Revision: 1,
		Strategy: strat,
		Members:  []RelayPoolMember{member},
	}
	if err := pool.Validate(); err != nil {
		t.Fatalf("valid RelayPool rejected: %v", err)
	}
	dupPool := pool
	dupPool.Members = []RelayPoolMember{member, member}
	if dupPool.Validate() == nil {
		t.Fatal("duplicate RelayPool member accepted")
	}

	base := Credential{ID: "native", AccountID: "acct-1", Kind: NativeCredential, User: "base", Identity: Identity("00000000-0000-4000-8000-000000000001"), EntryID: "entry-1", Enabled: true}
	route := Credential{ID: "route", AccountID: "acct-1", Kind: RouteCredential, User: RouteUser("g-1"), Identity: Identity("00000000-0000-4000-8000-000000000002"), EntryID: "entry-1", EgressID: "landing-1", Enabled: true}
	grant := RouteGrant{ID: "g-1", AccountID: "acct-1", EntryID: "entry-1", EgressID: "landing-1", RelayPoolID: "pool-hk", InboundTag: "meridian-entry", Base: base, Route: route, Mode: FixedMode, Enabled: true, DesiredRev: 1}
	if err := grant.Validate(); err != nil {
		t.Fatalf("pooled RouteGrant rejected: %v", err)
	}
	grant.ClientChainID = "legacy-chain"
	if grant.Validate() == nil {
		t.Fatal("RouteGrant accepted both ClientChainID and RelayPoolID")
	}

	// EntryRelayEdge requires exact matching Source for sendThrough.
	edge := EntryRelayEdge{
		ID:          "re-a",
		RelayNodeID: "relay-a",
		Source:      "2001:4860:4860::8888",
		Address:     "2001:4860:4860::1111",
		Port:        RelayPoolPort,
		Password:    eihPass,
	}
	if err := edge.Validate(); err != nil {
		t.Fatalf("valid EntryRelayEdge rejected: %v", err)
	}
	for _, mutate := range []func(*EntryRelayEdge){
		func(e *EntryRelayEdge) { e.Source = "" },
		func(e *EntryRelayEdge) { e.Source = "8.8.4.4" },
		func(e *EntryRelayEdge) { e.Source = e.Address },
	} {
		badEdge := edge
		mutate(&badEdge)
		if badEdge.Validate() == nil {
			t.Fatalf("invalid EntryRelayEdge source accepted: %+v", badEdge)
		}
	}

	poolKey := PooledRouteKey("g-1")
	ep := EntryRelayPool{
		Key:       poolKey,
		GrantID:   "g-1",
		AccountID: "acct-1",
		PoolID:    "pool-hk",
		EgressID:  "landing-1",
		Strategy:  strat,
		Candidates: []EntryPoolCandidate{{
			RelayNodeID:    "relay-a",
			RelayEdgeID:    "re-a",
			LandingAddress: "2606:4700:4700::1111",
			LandingPort:    RelayPoolPort,
			LandingPass:    eihPass,
		}},
	}
	if err := ep.Validate(); err != nil {
		t.Fatalf("valid EntryRelayPool rejected: %v", err)
	}
	badEP := ep
	badEP.Key = "pool-wrong"
	if badEP.Validate() == nil {
		t.Fatal("EntryRelayPool accepted mismatched Key")
	}
	badEP = ep
	badEP.Candidates = []EntryPoolCandidate{{
		RelayNodeID:    "landing-1",
		RelayEdgeID:    "re-a",
		LandingAddress: "2606:4700:4700::1111",
		LandingPort:    RelayPoolPort,
		LandingPass:    eihPass,
	}}
	if badEP.Validate() == nil {
		t.Fatal("EntryRelayPool accepted self-relay")
	}
}

func TestRenderXrayConfigurationRelayPoolsAndObservatory(t *testing.T) {
	nativeID := "00000000-0000-4000-8000-000000000001"
	r1ID := "00000000-0000-4000-8000-000000000011"
	r2ID := "00000000-0000-4000-8000-000000000012"
	r3ID := "00000000-0000-4000-8000-000000000013"
	r4ID := "00000000-0000-4000-8000-000000000014"
	r5ID := "00000000-0000-4000-8000-000000000015"
	native := Credential{ID: "native", AccountID: "acct", Kind: NativeCredential, User: "base", Identity: Identity(nativeID), EntryID: "entry", Enabled: true}
	rc1 := Credential{ID: "rc1", AccountID: "acct", Kind: RouteCredential, User: RouteUser("g-l1"), Identity: Identity(r1ID), EntryID: "entry", EgressID: "l1", Enabled: true}
	rc2 := Credential{ID: "rc2", AccountID: "acct", Kind: RouteCredential, User: RouteUser("g-l1-alt"), Identity: Identity(r2ID), EntryID: "entry", EgressID: "l1", Enabled: true}
	rc3 := Credential{ID: "rc3", AccountID: "acct", Kind: RouteCredential, User: RouteUser("g-l2"), Identity: Identity(r3ID), EntryID: "entry", EgressID: "l2", Enabled: true}
	rc4 := Credential{ID: "rc4", AccountID: "acct", Kind: RouteCredential, User: RouteUser("g-empty"), Identity: Identity(r4ID), EntryID: "entry", EgressID: "l3", Enabled: true}
	rc5 := Credential{ID: "rc5", AccountID: "acct", Kind: RouteCredential, User: RouteUser("g-disabled"), Identity: Identity(r5ID), EntryID: "entry", EgressID: "l1", Enabled: false}

	// g1 and g1Alt share (acct, pool-a, l1, TCP) but target distinct LandingAddress/exits.
	g1 := RouteGrant{ID: "g-l1", AccountID: "acct", EntryID: "entry", EgressID: "l1", RelayPoolID: "pool-a", InboundTag: "meridian-entry", Base: native, Route: rc1, Mode: FixedMode, Enabled: true, DesiredRev: 1}
	g1Alt := RouteGrant{ID: "g-l1-alt", AccountID: "acct", EntryID: "entry", EgressID: "l1", RelayPoolID: "pool-a", InboundTag: "meridian-entry", Base: native, Route: rc2, Mode: FixedMode, Enabled: true, DesiredRev: 1}
	g2 := RouteGrant{ID: "g-l2", AccountID: "acct", EntryID: "entry", EgressID: "l2", RelayPoolID: "pool-a", UDP: true, InboundTag: "meridian-entry", Base: native, Route: rc3, Mode: FixedMode, Enabled: true, DesiredRev: 1}
	g3 := RouteGrant{ID: "g-empty", AccountID: "acct", EntryID: "entry", EgressID: "l3", RelayPoolID: "pool-empty", InboundTag: "meridian-entry", Base: native, Route: rc4, Mode: FixedMode, Enabled: true, DesiredRev: 1}
	gDisabled := RouteGrant{ID: "g-disabled", AccountID: "acct", EntryID: "entry", EgressID: "l1", RelayPoolID: "pool-a", InboundTag: "meridian-entry", Base: native, Route: rc5, Mode: FixedMode, Enabled: false, DesiredRev: 1}

	if g1.PoolKey() == g1Alt.PoolKey() {
		t.Fatal("distinct grants sharing (acct, pool, egress) collided on PoolKey")
	}

	edgeA := EntryRelayEdge{ID: "re-a-tcp", RelayNodeID: "relay-a", Source: "2001:4860:4860::8888", Address: "2001:4860:4860::1111", Port: RelayPoolPort, Password: testSS2022Key16(1) + ":" + testSS2022Key16(2)}
	edgeB := EntryRelayEdge{ID: "re-b-tcp", RelayNodeID: "relay-b", Source: "2001:4860:4860::8888", Address: "2001:4860:4860::2222", Port: RelayPoolPort, Password: testSS2022Key16(3) + ":" + testSS2022Key16(4)}
	obs := ObservatoryConfig{Destination: DefaultObservatoryDestination, IntervalSec: 15, Sampling: 3, TimeoutSec: 5}
	p1 := EntryRelayPool{
		Key:       g1.PoolKey(),
		GrantID:   g1.ID,
		AccountID: "acct",
		PoolID:    "pool-a",
		EgressID:  "l1",
		Strategy:  RelayPoolStrategy{Expected: 2, MaxRTTMS: 450, Tolerance: 0.05},
		Candidates: []EntryPoolCandidate{
			{RelayNodeID: "relay-a", RelayEdgeID: edgeA.ID, LandingAddress: "2606:4700:4700::1111", LandingPort: RelayPoolPort, LandingPass: testSS2022Key16(5) + ":" + testSS2022Key16(6)},
			{RelayNodeID: "relay-b", RelayEdgeID: edgeB.ID, LandingAddress: "2606:4700:4700::1111", LandingPort: RelayPoolPort, LandingPass: testSS2022Key16(5) + ":" + testSS2022Key16(7)},
		},
	}
	p1Alt := EntryRelayPool{
		Key:       g1Alt.PoolKey(),
		GrantID:   g1Alt.ID,
		AccountID: "acct",
		PoolID:    "pool-a",
		EgressID:  "l1",
		Strategy:  RelayPoolStrategy{Expected: 2, MaxRTTMS: 450, Tolerance: 0.05},
		Candidates: []EntryPoolCandidate{
			{RelayNodeID: "relay-a", RelayEdgeID: edgeA.ID, LandingAddress: "2620:fe::fe", LandingPort: RelayPoolPort, LandingPass: testSS2022Key16(5) + ":" + testSS2022Key16(10)},
			{RelayNodeID: "relay-b", RelayEdgeID: edgeB.ID, LandingAddress: "2620:fe::fe", LandingPort: RelayPoolPort, LandingPass: testSS2022Key16(5) + ":" + testSS2022Key16(11)},
		},
	}
	p2 := EntryRelayPool{
		Key:       g2.PoolKey(),
		GrantID:   g2.ID,
		AccountID: "acct",
		PoolID:    "pool-a",
		EgressID:  "l2",
		UDP:       true,
		Strategy:  RelayPoolStrategy{Expected: 1, MaxRTTMS: 500, Tolerance: 0.1},
		Candidates: []EntryPoolCandidate{
			{RelayNodeID: "relay-a", RelayEdgeID: edgeA.ID, LandingAddress: "2606:4700:4700::1001", LandingPort: RelayPoolPort, LandingPass: testSS2022Key16(8) + ":" + testSS2022Key16(9)},
		},
	}
	p3 := EntryRelayPool{
		Key:       g3.PoolKey(),
		GrantID:   g3.ID,
		AccountID: "acct",
		PoolID:    "pool-empty",
		EgressID:  "l3",
		Strategy:  DefaultRelayPoolStrategy(1),
	}

	plan := XrayPlan{
		Revision: 2,
		RealityEndpoints: []RealityEndpoint{{
			ID: "ep", EntryID: "entry", InboundTag: "meridian-entry",
			ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort,
			AdvertiseHost: "entry.example.com", AdvertisePort: 443,
			Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
			PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}, Fingerprint: "chrome",
		}},
		Credentials: []CredentialMaterial{
			{Credential: native, ProtocolID: nativeID},
			{Credential: rc1, ProtocolID: r1ID},
			{Credential: rc2, ProtocolID: r2ID},
			{Credential: rc3, ProtocolID: r3ID},
			{Credential: rc4, ProtocolID: r4ID},
			{Credential: rc5, ProtocolID: r5ID},
		},
		// gDisabled intentionally has NO EntryRelayPool entry (deleted/disabled tombstone semantics).
		Grants:      []RouteGrant{g1, g1Alt, g2, g3, gDisabled},
		Observatory: &obs,
		RelayEdges:  []EntryRelayEdge{edgeA, edgeB},
		RelayPools:  []EntryRelayPool{p1, p1Alt, p2, p3},
	}

	if _, err := BuildDesiredArtifactVersion(plan, 63); err == nil {
		t.Fatal("legacy render version 63 accepted RelayPools")
	}
	if _, err := BuildDesiredArtifactVersion(plan, 127); err == nil {
		t.Fatal("legacy render version 127 accepted RelayPools")
	}

	raw, err := RenderXrayConfiguration(plan)
	if err != nil {
		t.Fatalf("RenderXrayConfiguration pooled plan failed: %v", err)
	}
	var cfg struct {
		API struct {
			Services []string `json:"services"`
		} `json:"api"`
		BurstObservatory *struct {
			SubjectSelector []string       `json:"subjectSelector"`
			PingConfig      map[string]any `json:"pingConfig"`
		} `json:"burstObservatory"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Balancers []map[string]any `json:"balancers"`
			Rules     []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal rendered pooled config: %v", err)
	}
	if !slices.Contains(cfg.API.Services, "ObservatoryService") {
		t.Fatalf("ObservatoryService missing from api.services: %v", cfg.API.Services)
	}
	if cfg.BurstObservatory == nil || len(cfg.BurstObservatory.SubjectSelector) != 3 {
		t.Fatalf("unexpected burstObservatory: %+v", cfg.BurstObservatory)
	}
	if slices.Contains(cfg.BurstObservatory.SubjectSelector, PoolCandidatePrefix(p3.Key)) {
		t.Fatal("empty pool prefix should not be observed")
	}
	if cfg.BurstObservatory.PingConfig["interval"] != "15s" || cfg.BurstObservatory.PingConfig["timeout"] != "5s" || cfg.BurstObservatory.PingConfig["connectivity"] != "" {
		t.Fatalf("unexpected pingConfig: %+v", cfg.BurstObservatory.PingConfig)
	}

	edgeCount := 0
	udpCandMux := false
	tcpCandNoMux := false
	for _, out := range cfg.Outbounds {
		tag, _ := out["tag"].(string)
		if strings.HasPrefix(tag, "relay-edge-") {
			edgeCount++
			if out["mux"] != nil || out["sendThrough"] != "2001:4860:4860::8888" {
				t.Fatalf("physical relay edge must carry sendThrough and no mux: %+v", out)
			}
		}
		if tag == PoolCandidateTag(p1.Key, 0) {
			stream, _ := out["streamSettings"].(map[string]any)
			sockopt, _ := stream["sockopt"].(map[string]any)
			if sockopt["dialerProxy"] != RelayEdgeOutboundTag(edgeA.ID) || out["mux"] != nil {
				t.Fatalf("unexpected TCP candidate outbound: %+v", out)
			}
			tcpCandNoMux = true
		}
		if tag == PoolCandidateTag(p2.Key, 0) {
			stream, _ := out["streamSettings"].(map[string]any)
			sockopt, _ := stream["sockopt"].(map[string]any)
			mux, _ := out["mux"].(map[string]any)
			if sockopt["dialerProxy"] != RelayEdgeOutboundTag(edgeA.ID) || mux == nil || mux["enabled"] != true || mux["xudpProxyUDP443"] != "reject" {
				t.Fatalf("unexpected UDP candidate outbound: %+v", out)
			}
			udpCandMux = true
		}
	}
	if edgeCount != 2 || !tcpCandNoMux || !udpCandMux {
		t.Fatalf("edgeCount=%d tcpCandNoMux=%v udpCandMux=%v", edgeCount, tcpCandNoMux, udpCandMux)
	}
	if len(cfg.Routing.Balancers) != 3 {
		t.Fatalf("expected 3 balancers (p1, p1Alt, p2; empty pool omitted), got %d", len(cfg.Routing.Balancers))
	}
	foundP1Bal := false
	for _, b := range cfg.Routing.Balancers {
		if b["tag"] == PoolBalancerTag(p1.Key) {
			foundP1Bal = true
			if b["fallbackTag"] != PoolCandidateTag(p1.Key, 0) {
				t.Fatalf("expected r0 fallbackTag, got %v", b["fallbackTag"])
			}
			stratMap, _ := b["strategy"].(map[string]any)
			settings, _ := stratMap["settings"].(map[string]any)
			if stratMap["type"] != "leastLoad" || settings["expected"] != float64(2) || settings["maxRTT"] != "450ms" || settings["tolerance"] != 0.05 {
				t.Fatalf("unexpected leastLoad settings: %+v", stratMap)
			}
		}
	}
	if !foundP1Bal {
		t.Fatal("p1 balancer missing")
	}

	g1Routed, g1AltRouted, g3Blocked := false, false, false
	for _, rule := range cfg.Routing.Rules {
		users, _ := rule["user"].([]any)
		if len(users) != 1 {
			continue
		}
		if users[0] == rc1.User && rule["balancerTag"] == PoolBalancerTag(p1.Key) && rule["outboundTag"] == nil {
			g1Routed = true
		}
		if users[0] == rc2.User && rule["balancerTag"] == PoolBalancerTag(p1Alt.Key) && rule["outboundTag"] == nil {
			g1AltRouted = true
		}
		if users[0] == rc4.User && rule["outboundTag"] == "blocked" && rule["balancerTag"] == nil {
			g3Blocked = true
		}
	}
	if !g1Routed || !g1AltRouted || !g3Blocked {
		t.Fatalf("unexpected routing rules: g1Routed=%v g1AltRouted=%v g3Blocked=%v", g1Routed, g1AltRouted, g3Blocked)
	}

	// All-empty pool plan must omit burstObservatory and ObservatoryService.
	emptyOnly := plan
	emptyOnly.Credentials = []CredentialMaterial{{Credential: native, ProtocolID: nativeID}, {Credential: rc4, ProtocolID: r4ID}}
	emptyOnly.Grants = []RouteGrant{g3}
	emptyOnly.RelayEdges = nil
	emptyOnly.RelayPools = []EntryRelayPool{p3}
	emptyRaw, err := RenderXrayConfiguration(emptyOnly)
	if err != nil {
		t.Fatalf("empty-only pooled plan failed: %v", err)
	}
	var emptyCfg struct {
		API struct {
			Services []string `json:"services"`
		} `json:"api"`
		BurstObservatory any `json:"burstObservatory"`
	}
	if err := json.Unmarshal(emptyRaw, &emptyCfg); err != nil {
		t.Fatal(err)
	}
	if emptyCfg.BurstObservatory != nil || slices.Contains(emptyCfg.API.Services, "ObservatoryService") {
		t.Fatalf("empty-only plan should not emit observatory: %+v", emptyCfg)
	}

	// Non-pooled plan remains byte-identical across versions 63, 127, and 255.
	plain := XrayPlan{
		Revision:         1,
		RealityEndpoints: plan.RealityEndpoints,
		Credentials:      []CredentialMaterial{{Credential: native, ProtocolID: nativeID}},
	}
	a63, err := BuildDesiredArtifactVersion(plain, 63)
	if err != nil {
		t.Fatal(err)
	}
	a127, err := BuildDesiredArtifactVersion(plain, 127)
	if err != nil {
		t.Fatal(err)
	}
	a255, err := BuildDesiredArtifactVersion(plain, XrayRenderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a63.Config, a127.Config) || !bytes.Equal(a63.Config, a255.Config) {
		t.Fatal("historical non-pooled Xray render bytes changed")
	}
}
