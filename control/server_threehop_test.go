package control

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// One pooled three-hop path alongside an existing direct peer covers isolation,
// single-port 24000 EIH admission, and XUDP authorization in schema v2.
func TestThreeHopServerPreservesDirectPeerAndEnforcesPoolAdmission(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }

	// Legacy single-relay ClientChainID grants are forbidden in v2.
	legacyGrant := grant
	legacyGrant.ClientChainID = "legacy-three-hop"
	if _, err := s.ChangeRoute(context.Background(), legacyGrant); err == nil {
		t.Fatal("v2 accepted retired legacy single-relay ClientChainID grant")
	}

	// Enroll a dedicated relay node and configure entry IPv6 source + observatory.
	relayCert := strings.Repeat("c", 64)
	rp := *artifact(1).Landing
	rp.Address = "100.64.0.4"
	rp.EgressIP = "2001:4860:4860::1111"
	rp.Sources = nil
	rp.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: "MDEyMzQ1Njc4OWFiY2RlZg==", PublicAddress: "9.9.9.10"}
	rd, err := NewDesired(rp)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "relay-example", CertificateID: relayCert, Desired: rd}); err != nil {
		t.Fatal(err)
	}
	relayIdentity := landing.PeerIdentity{ID: "relay-mesh", PublicKey: "nodekey:relay", Address: rp.Address}
	targetIdentity := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	reportNode := func(cert string, id landing.PeerIdentity) {
		t.Helper()
		n := s.nodes[cert]
		if _, err := s.Exchange(context.Background(), cert, &Observation{
			AppliedReceipt:          glivela.AppliedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256, RuntimeReady: true},
			MaxLandingRenderVersion: landing.RenderVersion,
			ManagementIdentity:      &id,
		}); err != nil {
			t.Fatal(err)
		}
	}
	reportNode(relayCert, relayIdentity)
	reportFreshEntry(t, s, entryCert)

	direct := s.nodes[entryCert].Desired.Entry.Peers[0]
	obs := glivela.DefaultObservatoryConfig()
	if _, err := s.ChangeEntryRelayConfig(context.Background(), EntryRelayConfigChange{
		EntryID:          grant.EntryID,
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config: glivela.EntryRelayConfig{
			SourceIPv6:  "2001:4860:4860::8888",
			Observatory: &obs,
		},
	}); err != nil {
		t.Fatal("configure entry observatory", err)
	}

	poolID := "pool-example"
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       poolID,
			Name:     "Example Relay Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(1),
			Members: []glivela.RelayPoolMember{{
				NodeID:        "relay-example",
				CertificateID: relayCert,
				IngressIPv6:   "2001:4860:4860::1111",
				EgressIPv6:    "2001:4860:4860::1111",
			}},
		},
	}); err != nil {
		t.Fatal("create relay pool", err)
	}

	grant.ID = "three-hop-pooled"
	grant.RelayPoolID = poolID
	grant.LandingAddress = "2606:4700:4700::1111"
	grant.ExpectedExit = "8.8.8.8"
	grant.EgressIP = "8.8.8.8"
	grant.Name = "Example via relay pool"
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("grant pooled three-hop", err)
	}

	// Control-plane admission check: BEFORE relay & landing report applied EIH
	// receipts, entry must NOT admit the candidate and must route to blocked.
	entry := s.nodes[entryCert]
	if len(entry.Desired.Entry.RelayPools) != 1 || len(entry.Desired.Entry.RelayPools[0].Candidates) != 0 || len(entry.Desired.Entry.RelayEdges) != 0 {
		t.Fatalf("candidate admitted before relay/landing EIH receipts: pools=%+v edges=%+v", entry.Desired.Entry.RelayPools, entry.Desired.Entry.RelayEdges)
	}
	if len(s.nodes[relayCert].Desired.Landing.EIHListeners) != 1 || len(s.nodes[targetCert].Desired.Landing.EIHListeners) != 1 {
		t.Fatal("EIH 24000 listeners not projected onto relay and landing")
	}

	// Report applied EIH receipts on relay first (still waiting on landing), then landing.
	reportNode(relayCert, relayIdentity)
	if len(s.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 0 {
		t.Fatal("candidate admitted before downstream landing confirmed EIH receipt")
	}
	reportNode(targetCert, targetIdentity)

	// Once BOTH relay & landing report fresh EIH receipts, Exchange automatically
	// admits the candidate onto entry.
	entry = s.nodes[entryCert]
	if len(entry.Desired.Entry.RelayPools) != 1 || len(entry.Desired.Entry.RelayPools[0].Candidates) != 1 || len(entry.Desired.Entry.RelayEdges) != 1 {
		t.Fatalf("candidate not admitted after both EIH receipts: pools=%+v edges=%+v", entry.Desired.Entry.RelayPools, entry.Desired.Entry.RelayEdges)
	}
	if !reflect.DeepEqual(direct, entry.Desired.Entry.Peers[0]) {
		t.Fatal("direct peer changed when adding pooled three-hop route")
	}

	// Native entry gates cover only direct peers, never startup-blocking gates for pooled relays.
	driver := &NativeEntryDriver{
		SystemdDriver: SystemdDriver{Role: "entry", WorkerUID: 990, WorkerGID: 990, Unit: "glivela-entry.service", WorkerUser: "glivela", Interface: "tailscale0"},
		Directory:     t.TempDir(),
	}
	gates, err := driver.gates(entry.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) != len(entry.Desired.EntryNetwork.Peers) {
		t.Fatalf("expected %d gates for direct peers only, got %d", len(entry.Desired.EntryNetwork.Peers), len(gates))
	}

	// Subscription contains the pooled route without dialer-proxy.
	r := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
	if r.Code != 200 || !strings.Contains(r.Body.String(), grant.Name) || strings.Contains(r.Body.String(), "dialer-proxy:") {
		t.Fatalf("pooled subscription missing or leaked dialer-proxy: code=%d body=%s", r.Code, r.Body.String())
	}

	// Rendered entry JSON has deduplicated relay-edge, dialerProxy candidate, leastLoad balancer, and burstObservatory.
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Balancers []map[string]any `json:"balancers"`
		} `json:"routing"`
		BurstObservatory any `json:"burstObservatory"`
	}
	if err := json.Unmarshal(entry.Desired.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BurstObservatory == nil || len(cfg.Routing.Balancers) != 1 {
		t.Fatalf("missing burstObservatory or balancer: %+v", cfg)
	}
	foundSendThrough := false
	for _, o := range cfg.Outbounds {
		tag, _ := o["tag"].(string)
		if strings.HasPrefix(tag, "relay-edge-") && o["sendThrough"] == "2001:4860:4860::8888" {
			foundSendThrough = true
		}
	}
	if !foundSendThrough {
		t.Fatal("entry relay-edge outbound missing sendThrough matching EntryRelayConfig.SourceIPv6")
	}

	// Enabling UDP updates ONLY downstream landing EIH user (with UDP=true) and
	// entry candidate mux, while relay EIH user stays TCP-only (UDP=false).
	beforeRelayEIH := s.nodes[relayCert].Desired.Landing.CloneEIHListeners()
	grant.ExpectedRevision = revision()
	grant.UDP = true
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("enable pooled three-hop UDP", err)
	}
	for _, u := range s.nodes[relayCert].Desired.Landing.EIHListeners[0].Users {
		if u.UDP || u.Role != "relay" {
			t.Fatalf("relay EIH user unexpectedly granted UDP or wrong role: %+v", u)
		}
	}
	if !slices.ContainsFunc(s.nodes[targetCert].Desired.Landing.EIHListeners[0].Users, func(u landing.EIHUser) bool {
		return u.Role == "landing" && u.UDP
	}) {
		t.Fatal("downstream landing EIH user missing UDP capability")
	}
	// Because UDP splits the relay-edge uPSK scope, report fresh receipts to admit the UDP candidate.
	if reflect.DeepEqual(beforeRelayEIH, s.nodes[relayCert].Desired.Landing.EIHListeners) {
		t.Fatal("expected UDP toggle to rotate relay-edge uPSK scope")
	}
	reportNode(relayCert, relayIdentity)
	reportNode(targetCert, targetIdentity)

	if err := json.Unmarshal(s.nodes[entryCert].Desired.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	udpOutbounds := 0
	for _, o := range cfg.Outbounds {
		if o["mux"] != nil {
			udpOutbounds++
			if o["streamSettings"] == nil {
				t.Fatal("UDP bypassed relay dialerProxy")
			}
		}
	}
	if udpOutbounds != 1 {
		t.Fatalf("expected 1 XUDP pooled candidate outbound, got %d", udpOutbounds)
	}
}
