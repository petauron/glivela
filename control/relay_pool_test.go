package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func enrollPoolTestLanding(t *testing.T, s *Store, nodeID, certID, tailnetIP, publicIPv4, egressIP string) landing.PeerIdentity {
	t.Helper()
	p := *artifact(1).Landing
	p.Address = tailnetIP
	p.EgressIP = egressIP
	p.Sources = nil
	p.Transport = glivela.PrivateTransport{
		Protocol:      "ss2022",
		Key:           "MDEyMzQ1Njc4OWFiY2RlZg==",
		PublicAddress: publicIPv4,
	}
	d, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: nodeID, CertificateID: certID, Desired: d}); err != nil {
		t.Fatal(err)
	}
	id := landing.PeerIdentity{ID: nodeID + "-mesh", PublicKey: "nodekey:" + nodeID, Address: tailnetIP}
	reportFreshLanding(t, s, certID, id)
	return id
}

func reportFreshLanding(t *testing.T, s *Store, certID string, id landing.PeerIdentity) {
	t.Helper()
	n := s.nodes[certID]
	if _, err := s.Exchange(context.Background(), certID, &Observation{
		AppliedReceipt:          glivela.AppliedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256, RuntimeReady: true},
		MaxLandingRenderVersion: landing.RenderVersion,
		ManagementIdentity:      &id,
	}); err != nil {
		t.Fatalf("reportFreshLanding(%s): %v", n.ID, err)
	}
}

func reportFreshEntry(t *testing.T, s *Store, entryCert string) {
	t.Helper()
	n := s.nodes[entryCert]
	obs := healthyEntryObservation(n.Desired, time.Now().UTC())
	obs.MaxEntryRenderVersion = glivela.XrayRenderVersion
	for id, peer := range obs.EntryHealth.Peers {
		peer.Status.LinkState = "authenticated"
		obs.EntryHealth.Peers[id] = peer
	}
	if _, err := s.Exchange(context.Background(), entryCert, &obs); err != nil {
		t.Fatalf("reportFreshEntry(%s): %v", n.ID, err)
	}
}

func TestRelayPoolPhysicalEdgeReuseAndCredentialIsolation(t *testing.T) {
	s, entryCert, landing1Cert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }

	relayACert := strings.Repeat("c", 64)
	relayBCert := strings.Repeat("d", 64)
	landing2Cert := strings.Repeat("e", 64)
	relayAID := enrollPoolTestLanding(t, s, "relay-a", relayACert, "100.64.0.21", "9.9.9.10", "2001:4860:4860::1111")
	relayBID := enrollPoolTestLanding(t, s, "relay-b", relayBCert, "100.64.0.22", "9.9.9.11", "2001:4860:4860::2222")
	landing2ID := enrollPoolTestLanding(t, s, "landing-2", landing2Cert, "100.64.0.23", "9.9.9.12", "8.8.8.8")
	landing1ID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	reportFreshEntry(t, s, entryCert)

	obs := glivela.DefaultObservatoryConfig()
	if _, err := s.ChangeEntryRelayConfig(context.Background(), EntryRelayConfigChange{
		EntryID:          grant.EntryID,
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config:           glivela.EntryRelayConfig{SourceIPv6: "2001:4860:4860::8888", Observatory: &obs},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       "pool-shared",
			Name:     "Shared Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(2),
			Members: []glivela.RelayPoolMember{
				{NodeID: "relay-a", CertificateID: relayACert, IngressIPv6: "2001:4860:4860::1111", EgressIPv6: "2001:4860:4860::1111"},
				{NodeID: "relay-b", CertificateID: relayBCert, IngressIPv6: "2001:4860:4860::2222", EgressIPv6: "2001:4860:4860::2222"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Create TWO grants for the SAME (entry, account, pool, landing-example) with
	// DISTINCT fixed EgressIPs, plus a third grant for landing-2.
	g1 := grant
	g1.ID = "pooled-l1-exit1"
	g1.RelayPoolID = "pool-shared"
	g1.LandingAddress = "2606:4700:4700::1111"
	g1.ExpectedExit = "8.8.8.8"
	g1.EgressIP = "8.8.8.8"
	g1.Name = "HK Exit 1"
	g1.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g1); err != nil {
		t.Fatal(err)
	}

	g1Alt := g1
	g1Alt.ID = "pooled-l1-exit2"
	g1Alt.ExpectedExit = "1.1.1.1"
	g1Alt.EgressIP = "1.1.1.1"
	g1Alt.Name = "HK Exit 2"
	g1Alt.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g1Alt); err != nil {
		t.Fatal(err)
	}

	g2 := g1
	g2.ID = "pooled-l2"
	g2.EgressID = "landing-2"
	g2.LandingAddress = "2606:4700:4700::1001"
	g2.Name = "JP via Pool"
	g2.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g2); err != nil {
		t.Fatal(err)
	}

	reportFreshLanding(t, s, relayACert, relayAID)
	reportFreshLanding(t, s, relayBCert, relayBID)
	reportFreshLanding(t, s, landing1Cert, landing1ID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)

	entry := s.nodes[entryCert]
	if len(entry.Desired.Entry.RelayPools) != 3 {
		t.Fatalf("expected 3 independent logical pooled routes (including 2 distinct exits on landing-example), got %d", len(entry.Desired.Entry.RelayPools))
	}
	if len(entry.Desired.Entry.RelayEdges) != 2 {
		t.Fatalf("expected 2 deduplicated physical relay edges across all 3 TCP grants, got %d", len(entry.Desired.Entry.RelayEdges))
	}
	for _, edge := range entry.Desired.Entry.RelayEdges {
		if edge.Source != "2001:4860:4860::8888" {
			t.Fatalf("physical relay edge missing configured entry source: %+v", edge)
		}
	}
	if len(s.nodes[relayACert].Desired.Landing.EIHListeners[0].Users) != 1 || len(s.nodes[relayACert].Desired.Landing.EIHListeners[0].Users[0].RelayTargets) != 2 {
		t.Fatalf("relay-a should share one TCP uPSK with 2 exact landing targets: %+v", s.nodes[relayACert].Desired.Landing.EIHListeners)
	}
	// landing-example must hold 4 distinct landing uPSKs: (relay-a, relay-b) x (exit1, exit2).
	if len(s.nodes[landing1Cert].Desired.Landing.EIHListeners[0].Users) != 4 {
		t.Fatalf("expected 4 distinct landing EIH users for 2 relays x 2 fixed exits, got %d", len(s.nodes[landing1Cert].Desired.Landing.EIHListeners[0].Users))
	}
	// Verify g1 and g1Alt candidates point to DIFFERENT landing uPSKs (never merged).
	var p1, p1Alt glivela.EntryRelayPool
	for _, ep := range entry.Desired.Entry.RelayPools {
		switch ep.GrantID {
		case g1.ID:
			p1 = ep
		case g1Alt.ID:
			p1Alt = ep
		}
	}
	if p1.Key == p1Alt.Key || p1.Candidates[0].LandingKey == p1Alt.Candidates[0].LandingKey {
		t.Fatal("two grants with distinct EgressIP on same landing were merged onto identical uPSK/pool")
	}

	// Enabling UDP on L2 splits its relay-edge uPSK from TCP-only L1.
	g2.UDP = true
	g2.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g2); err != nil {
		t.Fatal(err)
	}
	if len(s.nodes[relayACert].Desired.Landing.EIHListeners[0].Users) != 2 {
		t.Fatalf("expected separate relay uPSKs for TCP and UDP scopes, got %d", len(s.nodes[relayACert].Desired.Landing.EIHListeners[0].Users))
	}
	reportFreshLanding(t, s, relayACert, relayAID)
	reportFreshLanding(t, s, relayBCert, relayBID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	if len(s.nodes[entryCert].Desired.Entry.RelayEdges) != 4 {
		t.Fatalf("expected 4 relay edges after TCP/UDP split, got %d", len(s.nodes[entryCert].Desired.Entry.RelayEdges))
	}

	// P2 #1: Same relay node configured in a second pool with a DIFFERENT IPv6
	// ingress & egress address must generate a distinct relay-edge credential ID
	// and separate EIHListener without colliding on EIHUser.ID or clobbering EgressIP.
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       "pool-alt-addr",
			Name:     "Alt Addr Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(1),
			Members:  []glivela.RelayPoolMember{{NodeID: "relay-a", CertificateID: relayACert, IngressIPv6: "2001:4860:4860::3333", EgressIPv6: "2001:4860:4860::3333"}},
		},
	}); err != nil {
		t.Fatalf("create second pool with distinct relay-a IPv6 failed: %v", err)
	}
	gAltAddr := g1
	gAltAddr.ID = "pooled-l2-alt-addr"
	gAltAddr.EgressID = "landing-2"
	gAltAddr.RelayPoolID = "pool-alt-addr"
	gAltAddr.LandingAddress = "2606:4700:4700::1001"
	gAltAddr.Name = "JP via Alt Addr"
	gAltAddr.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), gAltAddr); err != nil {
		t.Fatalf("grant on second relay-a IPv6 address failed: %v", err)
	}
	if len(s.nodes[relayACert].Desired.Landing.EIHListeners) != 2 {
		t.Fatalf("expected 2 distinct EIHListeners on relay-a for distinct ingress IPv6s, got %d", len(s.nodes[relayACert].Desired.Landing.EIHListeners))
	}
	id0 := s.nodes[relayACert].Desired.Landing.EIHListeners[0].Users[0].ID
	id1 := s.nodes[relayACert].Desired.Landing.EIHListeners[1].Users[0].ID
	if id0 == id1 {
		t.Fatal("distinct relay ingress/egress addresses collided on identical EIHUser.ID")
	}
	// P2 #2: Targeting the EXACT SAME landing-example (same LandingAddress & EgressIP)
	// via pool-alt-addr (same relay-a node, different relayEgress source IP) must
	// also produce a distinct landing-hop EIHUser.ID without source conflict!
	gAltSameLanding := g1
	gAltSameLanding.ID = "pooled-l1-alt-src"
	gAltSameLanding.RelayPoolID = "pool-alt-addr"
	gAltSameLanding.Name = "HK via Alt Relay Egress"
	gAltSameLanding.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), gAltSameLanding); err != nil {
		t.Fatalf("grant on same landing via distinct relay-a egress IP failed: %v", err)
	}
	if len(s.nodes[landing1Cert].Desired.Landing.EIHListeners[0].Users) != 5 {
		t.Fatalf("expected 5 distinct landing EIH users on landing-example (4 original + 1 alt relayEgress), got %d", len(s.nodes[landing1Cert].Desired.Landing.EIHListeners[0].Users))
	}

	// Business() inventory must remain strictly secret-free.
	inv := s.Business()
	rawInv, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	invText := string(rawInv)
	for _, key := range s.business.material.EIHNodeKeys {
		if strings.Contains(invText, key.ServerKey) {
			t.Fatal("Business inventory leaked EIH ServerKey")
		}
	}
	for _, secret := range s.business.material.RelayPoolCredentials {
		if strings.Contains(invText, secret) {
			t.Fatal("Business inventory leaked RelayPool uPSK")
		}
	}
	for _, secret := range s.business.material.ProtocolSecrets {
		if strings.Contains(invText, secret) {
			t.Fatal("Business inventory leaked ProtocolSecret")
		}
	}
}

func TestRelayPoolMemberDrainIsolatesDualRoleFixedLanding(t *testing.T) {
	s, entryCert, dualCert, directGrant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }

	directGrant.ID = "direct-dual"
	directGrant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), directGrant); err != nil {
		t.Fatal(err)
	}
	_, grants, err := effectiveBusinessCredentials(s.business.material, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	directUUID := s.business.material.ProtocolSecrets[grants[directGrant.ID].Route.ID]

	landing2Cert := strings.Repeat("e", 64)
	landing2ID := enrollPoolTestLanding(t, s, "landing-2", landing2Cert, "100.64.0.23", "9.9.9.12", "8.8.8.8")
	dualID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	reportFreshEntry(t, s, entryCert)

	obs := glivela.DefaultObservatoryConfig()
	if _, err := s.ChangeEntryRelayConfig(context.Background(), EntryRelayConfigChange{
		EntryID:          directGrant.EntryID,
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config:           glivela.EntryRelayConfig{SourceIPv6: "2001:4860:4860::8888", Observatory: &obs},
	}); err != nil {
		t.Fatal(err)
	}

	pool := glivela.RelayPool{
		ID:       "pool-dual",
		Name:     "Dual Role Pool",
		Strategy: glivela.DefaultRelayPoolStrategy(1),
		Members: []glivela.RelayPoolMember{{
			NodeID:        "landing-example",
			CertificateID: dualCert,
			IngressIPv6:   "2001:4860:4860::1111",
			EgressIPv6:    "2001:4860:4860::1111",
		}},
	}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{Pool: pool}); err != nil {
		t.Fatal(err)
	}

	pooledGrant := directGrant
	pooledGrant.ID = "pooled-via-dual"
	pooledGrant.EgressID = "landing-2"
	pooledGrant.RelayPoolID = "pool-dual"
	pooledGrant.LandingAddress = "2606:4700:4700::1001"
	pooledGrant.ExpectedExit = "8.8.8.8"
	pooledGrant.Name = "L2 via Dual"
	pooledGrant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), pooledGrant); err != nil {
		t.Fatal(err)
	}

	reportFreshLanding(t, s, dualCert, dualID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	if len(s.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 1 {
		t.Fatal("dual-role relay candidate not admitted")
	}

	pool.Members[0].Drained = true
	pool.Members[0].DrainReason = "line-jitter"
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{Pool: pool, ExpectedRevision: 1}); err != nil {
		t.Fatal("drain member", err)
	}
	if len(s.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 0 {
		t.Fatal("drained member remained in active pool candidates")
	}
	if len(s.nodes[dualCert].Desired.Landing.EIHListeners) != 0 {
		t.Fatal("drained member retained relay EIH listener")
	}
	sub := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
	if sub.Code != 200 || !strings.Contains(sub.Body.String(), directUUID) {
		t.Fatalf("member-level drain wrongly withdrew dual-role fixed-landing subscription: code=%d", sub.Code)
	}

	availRev := s.Business().Availability.Revision
	if err := s.SetAvailability("landing-example", "maintenance", time.Time{}, availRev); err != nil {
		t.Fatal("set node maintenance", err)
	}
	pool.Members[0].Drained = false
	pool.Members[0].DrainReason = ""
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{Pool: pool, ExpectedRevision: 2}); err != nil {
		t.Fatal("undrain while node in maintenance", err)
	}
	if len(s.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 0 {
		t.Fatal("node in maintenance admitted back into relay pool")
	}
	sub = getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
	if strings.Contains(sub.Body.String(), directUUID) {
		t.Fatal("node-level maintenance did not withdraw fixed-landing subscription")
	}
}

func TestRelayPoolOfflineMemberRemovalUnreferencedGCAndEmptyPoolBlocked(t *testing.T) {
	s, entryCert, landing1Cert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }

	relayACert := strings.Repeat("c", 64)
	relayBCert := strings.Repeat("d", 64)
	landing2Cert := strings.Repeat("e", 64)
	relayAID := enrollPoolTestLanding(t, s, "relay-a", relayACert, "100.64.0.21", "9.9.9.10", "2001:4860:4860::1111")
	relayBID := enrollPoolTestLanding(t, s, "relay-b", relayBCert, "100.64.0.22", "9.9.9.11", "2001:4860:4860::2222")
	landing2ID := enrollPoolTestLanding(t, s, "landing-2", landing2Cert, "100.64.0.23", "9.9.9.12", "8.8.8.8")
	landing1ID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	reportFreshEntry(t, s, entryCert)

	obs := glivela.DefaultObservatoryConfig()
	if _, err := s.ChangeEntryRelayConfig(context.Background(), EntryRelayConfigChange{
		EntryID:          grant.EntryID,
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config:           glivela.EntryRelayConfig{SourceIPv6: "2001:4860:4860::8888", Observatory: &obs},
	}); err != nil {
		t.Fatal(err)
	}

	memberA := glivela.RelayPoolMember{NodeID: "relay-a", CertificateID: relayACert, IngressIPv6: "2001:4860:4860::1111", EgressIPv6: "2001:4860:4860::1111"}
	memberB := glivela.RelayPoolMember{NodeID: "relay-b", CertificateID: relayBCert, IngressIPv6: "2001:4860:4860::2222", EgressIPv6: "2001:4860:4860::2222"}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{ID: "pool-a", Name: "Pool A", Strategy: glivela.DefaultRelayPoolStrategy(2), Members: []glivela.RelayPoolMember{memberA, memberB}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{ID: "pool-b", Name: "Pool B", Strategy: glivela.DefaultRelayPoolStrategy(1), Members: []glivela.RelayPoolMember{memberA}},
	}); err != nil {
		t.Fatal(err)
	}

	g1 := grant
	g1.ID = "route-pool-a"
	g1.RelayPoolID = "pool-a"
	g1.LandingAddress = "2606:4700:4700::1111"
	g1.ExpectedExit = "8.8.8.8"
	g1.EgressIP = "8.8.8.8"
	g1.Name = "Pool A Route"
	g1.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g1); err != nil {
		t.Fatal(err)
	}
	g2 := g1
	g2.ID = "route-pool-b"
	g2.EgressID = "landing-2"
	g2.RelayPoolID = "pool-b"
	g2.LandingAddress = "2606:4700:4700::1001"
	g2.Name = "Pool B Route"
	g2.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g2); err != nil {
		t.Fatal(err)
	}

	reportFreshLanding(t, s, relayACert, relayAID)
	reportFreshLanding(t, s, relayBCert, relayBID)
	reportFreshLanding(t, s, landing1Cert, landing1ID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	reportFreshEntry(t, s, entryCert)

	// Transient heartbeat blip on an active candidate must NOT drop it or bounce entry revision.
	revBeforeBlip := s.nodes[entryCert].Desired.Revision
	s.mu.Lock()
	bNode := s.nodes[relayBCert]
	bNode.ReportedAt = time.Now().UTC().Add(-24 * time.Hour)
	s.nodes[relayBCert] = bNode
	if err := s.reconcileOwnedEntriesLocked(time.Now().UTC()); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	if s.nodes[entryCert].Desired.Revision != revBeforeBlip {
		t.Fatal("transient relay heartbeat blip unexpectedly restarted entry")
	}
	reportFreshLanding(t, s, relayBCert, relayBID)

	// Mark relay-a offline and remove it from pool-a immediately.
	s.mu.Lock()
	aNode := s.nodes[relayACert]
	aNode.ReportedAt = time.Now().UTC().Add(-24 * time.Hour)
	s.nodes[relayACert] = aNode
	s.mu.Unlock()

	hopRemovedID := landingHopCredentialID(g1.EntryID, g1.AccountID, "relay-a", "2001:4860:4860::1111", g1.EgressID, g1.LandingAddress, g1.EgressIP, false)
	hopSharedID := landingHopCredentialID(g2.EntryID, g2.AccountID, "relay-a", "2001:4860:4860::1111", g2.EgressID, g2.LandingAddress, g2.EgressIP, false)
	if s.business.material.RelayPoolCredentials[hopRemovedID] == "" || s.business.material.RelayPoolCredentials[hopSharedID] == "" {
		t.Fatal("expected both landing hop uPSKs before removal")
	}

	res, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool:             glivela.RelayPool{ID: "pool-a", Name: "Pool A", Strategy: glivela.DefaultRelayPoolStrategy(1), Members: []glivela.RelayPoolMember{memberB}},
		ExpectedRevision: 1,
	})
	if err != nil {
		t.Fatalf("offline member removal refused: %v", err)
	}
	if res.Revocation.Complete || !slices.Equal(res.Revocation.PendingEntries, []string{"entry-example"}) || !slices.Equal(res.Revocation.PendingLandings, []string{"landing-example"}) {
		t.Fatalf("unexpected pending revocation status: %+v", res.Revocation)
	}
	if s.business.material.RelayPoolCredentials[hopRemovedID] != "" {
		t.Fatal("unreferenced landing hop uPSK was not garbage-collected")
	}
	if s.business.material.RelayPoolCredentials[hopSharedID] == "" {
		t.Fatal("uPSK still referenced by pool-b was wrongly garbage-collected")
	}

	reportFreshLanding(t, s, landing1Cert, landing1ID)
	reportFreshEntry(t, s, entryCert)
	s.mu.Lock()
	revDone := s.poolRevocationStatusLocked("pool-a", time.Now().UTC())
	s.mu.Unlock()
	if !revDone.Complete {
		t.Fatalf("revocation should complete without waiting for offline relay-a: %+v", revDone)
	}

	// Removing last member keeps Grant.ID, UUID, subscription, and traffic intact while routing to blocked.
	_, beforeGrants, _ := effectiveBusinessCredentials(s.business.material, time.Now().UTC())
	beforeRouteCredID := beforeGrants[g1.ID].Route.ID
	beforeUUID := s.business.material.ProtocolSecrets[beforeRouteCredID]
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool:             glivela.RelayPool{ID: "pool-a", Name: "Pool A", Strategy: glivela.DefaultRelayPoolStrategy(1), Members: []glivela.RelayPoolMember{}},
		ExpectedRevision: 2,
	}); err != nil {
		t.Fatalf("remove last relay member failed: %v", err)
	}
	if s.business.material.ProtocolSecrets[beforeRouteCredID] != beforeUUID {
		t.Fatal("emptying pool changed route UUID")
	}
	sub := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
	if sub.Code != 200 || !strings.Contains(sub.Body.String(), beforeUUID) {
		t.Fatal("emptying pool dropped subscription route identity")
	}
	var cfg struct {
		Routing struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(s.nodes[entryCert].Desired.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	blocked := false
	for _, r := range cfg.Routing.Rules {
		users, _ := r["user"].([]any)
		if len(users) == 1 && users[0] == glivela.RouteUser(g1.ID) && r["outboundTag"] == "blocked" && r["balancerTag"] == nil {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("empty authorized pool did not fail closed to blocked")
	}

	// P2 #1: Disabling and deleting a pooled route must succeed cleanly and allow pool deletion.
	g1.Enabled = false
	g1.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g1); err != nil {
		t.Fatalf("disable pooled route failed: %v", err)
	}
	reportFreshEntry(t, s, entryCert)
	g1.Delete = true
	g1.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g1); err != nil {
		t.Fatalf("delete disabled pooled route failed: %v", err)
	}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool:             glivela.RelayPool{ID: "pool-a"},
		ExpectedRevision: 3,
		Delete:           true,
	}); err != nil {
		t.Fatalf("delete unreferenced relay pool after route deletion failed: %v", err)
	}
}

func TestForwardMigrationV1ThreeHopToV2RelayPool(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	relayCert := strings.Repeat("c", 64)
	relayID := enrollPoolTestLanding(t, s, "relay-example", relayCert, "100.64.0.4", "9.9.9.10", "2001:4860:4860::1111")
	targetID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	relayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 16))
	twoHopKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))
	chainID, port, serverIPv6, exit := "legacy-three-hop", 24001, "2606:4700:4700::1111", "8.8.8.8"
	relay := &glivela.ClientChainRelay{
		NodeID:        "relay-example",
		CertificateID: relayCert,
		Port:          port,
		Key:           relayKey,
		SourceIPv6:    "2001:4860:4860::8888",
		ServerIPv6:    "2001:4860:4860::1111",
	}

	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	network := entry.Desired.EntryNetwork.clone()
	twoHopPeer := plan.Peers[0]
	twoHopPeer.Port = 24002
	twoHopPeer.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: twoHopKey, PublicAddress: "2606:4700:4700::1001", Port: 24002, ClientListenerID: "twohop-keep"}
	plan.Peers[0] = twoHopPeer

	threeHopPeer := twoHopPeer
	threeHopPeer.ClientChainID = chainID
	threeHopPeer.Relay = relay
	threeHopPeer.Port = port
	threeHopPeer.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: serverIPv6, Port: port, ClientListenerID: chainID}
	plan.Peers = append(plan.Peers, threeHopPeer)

	npeer := network.Peers[0]
	npeer.ClientChainID = chainID
	npeer.RelayIdentity = &relayID
	network.Peers = append(network.Peers, npeer)

	baseIdx := slices.IndexFunc(plan.Credentials, func(c glivela.CredentialMaterial) bool {
		return c.Credential.Kind == glivela.NativeCredential && c.Credential.AccountID == grant.AccountID && c.Credential.EntryID == grant.EntryID
	})
	if baseIdx < 0 {
		t.Fatal("missing native base credential")
	}
	baseCred := plan.Credentials[baseIdx]
	routeUUID := "00000000-0000-4000-8000-000000000240"
	routeCred := glivela.Credential{ID: "cred-legacy-threehop", AccountID: grant.AccountID, Kind: glivela.RouteCredential, User: glivela.RouteUser("grant-legacy-threehop"), Identity: glivela.Identity(routeUUID), EntryID: grant.EntryID, EgressID: grant.EgressID, Enabled: true}
	v1Grant := glivela.RouteGrant{ID: "grant-legacy-threehop", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID, ClientChainID: chainID, UDP: true, InboundTag: plan.RealityEndpoints[0].InboundTag, Base: baseCred.Credential, Route: routeCred, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1}
	plan.Credentials = append(plan.Credentials, glivela.CredentialMaterial{Credential: routeCred, ProtocolID: routeUUID})
	plan.Grants = append(plan.Grants, v1Grant)
	plan.Revision++
	var err error
	entry.Desired, err = NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal(err)
	}
	entryRevBeforeUpgrade := entry.Desired.Revision

	relayListener := glivela.TransportListener{ID: chainID, Port: port, Key: relayKey, Source: relay.SourceIPv6, Transport: "ipv6-ss2022", Address: relay.ServerIPv6}
	targetListener := glivela.TransportListener{ID: chainID, Port: port, Key: key, Source: relay.ServerIPv6, Transport: "ipv6-ss2022", Address: serverIPv6, EgressIP: exit}
	threeHopRes := glivela.ServerTransport{
		ID: chainID, Name: "Legacy Three Hop", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID,
		EntryCertificateID: entryCert, LandingCertificateID: targetCert,
		Peer: threeHopPeer, ExpectedExit: npeer.ExpectedExit,
		Listener:      targetListener,
		RelayListener: &relayListener,
	}
	twoHopRes := glivela.ServerTransport{
		ID: "twohop-keep", Name: "Two Hop Keep", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID,
		EntryCertificateID: entryCert, LandingCertificateID: targetCert,
		Peer: twoHopPeer, ExpectedExit: network.Peers[0].ExpectedExit,
		Listener: glivela.TransportListener{ID: "twohop-keep", Port: 24002, Key: twoHopKey, Source: "2001:4860:4860::8888", Transport: "ipv6-ss2022", Address: "2606:4700:4700::1001", EgressIP: exit},
	}

	// Pre-install legacy 24001 listeners on relay and landing so the running v1 path is active.
	rNode := s.nodes[relayCert]
	rp := *rNode.Desired.clone().Landing
	rp.Revision++
	rp.ClientListeners = []landing.ClientListener{relayListener}
	rNode.Desired, err = NewDesired(rp)
	if err != nil {
		t.Fatal(err)
	}
	// Mark relay OFFLINE and both nodes as pre-upgrade v1 (MaxLandingRenderVersion=0)
	// to prove controller startup changes ZERO live runtimes!
	rNode.Receipt = nil
	rNode.MaxLandingRenderVersion = 0
	rNode.ReportedAt = time.Now().UTC().Add(-24 * time.Hour)
	relayRevBeforeUpgrade := rNode.Desired.Revision
	tNode := s.nodes[targetCert]
	tp := *tNode.Desired.clone().Landing
	tp.Revision++
	tp.ClientListeners = []landing.ClientListener{targetListener}
	tp.UDPOverTCPListeners = []string{chainID}
	tNode.Desired, err = NewDesired(tp)
	if err != nil {
		t.Fatal(err)
	}
	tNode.Receipt = nil
	tNode.MaxLandingRenderVersion = 0
	targetRevBeforeUpgrade := tNode.Desired.Revision

	v1Mat := s.business.material
	v1Mat.ServerTransportVersion = 1
	v1Mat.ServerTransports = map[string]glivela.ServerTransport{chainID: threeHopRes, "twohop-keep": twoHopRes}
	accounts := slices.Clone(v1Mat.Plan.Accounts)
	accounts[0].Account.Plan.TotalBytes = 100000
	accounts[0].Credentials = append(slices.Clone(accounts[0].Credentials), routeCred)
	accounts[0].Grants = append(slices.Clone(accounts[0].Grants), v1Grant)
	accounts[0].Usage = append(slices.Clone(accounts[0].Usage), glivela.UsageMember{CredentialID: routeCred.ID, Active: true, Observed: 12345})
	v1Mat.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		t.Fatal(err)
	}
	v1Mat.ProtocolSecrets[routeCred.ID] = routeUUID
	v1Mat.TrafficCounters[routeCred.ID] = glivela.ImportTrafficCounters{UploadBytes: 4000, DownloadBytes: 8345, RawUploadBytes: 4000, RawDownloadBytes: 8345}
	v1Mat.SubscriptionOrders = map[string]glivela.SubscriptionOrder{
		grant.AccountID: {Revision: 2, IDs: []string{"route/" + v1Grant.ID}},
	}
	if err := v1Mat.Validate(); err != nil {
		t.Fatalf("v1 material invalid: %v", err)
	}

	dir := filepath.Dir(s.path)
	keyPath := filepath.Join(dir, "business.key")
	storageKey, err := readBusinessKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	v1Sealed, err := glivela.SealImportMaterial(v1Mat, storageKey, s.business.snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	origRaw, err := readBusinessCheckpointFile(dir, "business.json")
	if err != nil {
		t.Fatal(err)
	}
	origEnv, err := checkpointEnvelope(origRaw)
	if err != nil {
		t.Fatal(err)
	}
	v1Env := stagedImport{Version: 1, SnapshotID: s.business.snapshotID, Sealed: v1Sealed}
	if origEnv.Version == 2 {
		v1Ledger, err := glivela.SealImportLedger(v1Mat, storageKey, s.business.snapshotID, origEnv.ArchiveSHA256)
		if err != nil {
			t.Fatal(err)
		}
		v1Env = stagedImport{Version: 2, SnapshotID: s.business.snapshotID, Sealed: v1Ledger, ArchiveSHA256: origEnv.ArchiveSHA256}
	}
	v1Checkpoint, err := json.Marshal(v1Env)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacePrivate(dir, "business.json", v1Checkpoint); err != nil {
		t.Fatal(err)
	}
	presRaw, err := json.Marshal(subscriptionPresentation{Version: 1, Names: map[string]string{chainID: "Issued HK Relay"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := replacePrivate(dir, subscriptionNamesFile, presRaw); err != nil {
		t.Fatal(err)
	}
	nodes := s.copy()
	nodes[entryCert] = entry
	nodes[relayCert] = rNode
	nodes[targetCert] = tNode
	if err := s.commit(nodes); err != nil {
		t.Fatal(err)
	}

	// 1. Controller startup (LoadBusiness) upgrades schema to v2 with PendingLegacyCutover=true
	// WITHOUT tearing down the running legacy three-hop entry peer or listeners (even while relay is offline!).
	reloaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.LoadBusiness(keyPath); err != nil {
		t.Fatalf("v1 -> v2 LoadBusiness migration failed: %v", err)
	}
	m2 := reloaded.business.material
	if m2.ServerTransportVersion != glivela.CurrentServerTransportVersion {
		t.Fatalf("expected schema version %d, got %d", glivela.CurrentServerTransportVersion, m2.ServerTransportVersion)
	}
	pr, hasPR := m2.PooledRoutes[v1Grant.ID]
	if !hasPR || !pr.PendingLegacyCutover || pr.LegacyTransportID != chainID || pr.RelayPoolID != "pool-relay-example" {
		t.Fatalf("expected PendingLegacyCutover PooledRoute after startup migration: %+v", m2.PooledRoutes)
	}
	if reloaded.nodes[entryCert].Desired.Revision != entryRevBeforeUpgrade ||
		reloaded.nodes[relayCert].Desired.Revision != relayRevBeforeUpgrade ||
		reloaded.nodes[targetCert].Desired.Revision != targetRevBeforeUpgrade {
		t.Fatalf("startup migration unexpectedly changed live runtimes: entry=%d/%d relay=%d/%d target=%d/%d",
			entryRevBeforeUpgrade, reloaded.nodes[entryCert].Desired.Revision,
			relayRevBeforeUpgrade, reloaded.nodes[relayCert].Desired.Revision,
			targetRevBeforeUpgrade, reloaded.nodes[targetCert].Desired.Revision)
	}
	if !slices.Contains(reloaded.nodes[relayCert].Desired.Landing.ClientListeners, relayListener) || !slices.Contains(reloaded.nodes[targetCert].Desired.Landing.ClientListeners, targetListener) {
		t.Fatal("startup migration withdrew running legacy three-hop listeners before explicit cutover")
	}
	// Explicit cutover MUST refuse while relay is offline / EIH receipts are pending.
	if _, err := reloaded.CutoverLegacyPooledRoute(context.Background(), v1Grant.ID); err == nil {
		t.Fatal("CutoverLegacyPooledRoute succeeded while relay was offline and EIH receipts were pending")
	}
	// Legacy subscription remains live during pending migration.
	subBefore := getSubscription(t, reloaded, "/sub/example-token?format=mihomo", "Mihomo")
	if subBefore.Code != 200 || !strings.Contains(subBefore.Body.String(), "Issued HK Relay") || !strings.Contains(subBefore.Body.String(), routeUUID) {
		t.Fatalf("legacy three-hop subscription broke before cutover: code=%d", subBefore.Code)
	}

	// 2. Upgrading relay & target to report MaxLandingRenderVersion projects
	// additive EIH 24000 listeners WITHOUT touching legacy 24001 listeners or entry;
	// CutoverLegacyPooledRoute still refuses until BOTH confirm applied EIH receipts.
	reportFreshLanding(t, reloaded, relayCert, relayID)
	reportFreshLanding(t, reloaded, targetCert, targetID)
	reportFreshEntry(t, reloaded, entryCert)
	if len(reloaded.nodes[relayCert].Desired.Landing.EIHListeners) != 1 || len(reloaded.nodes[targetCert].Desired.Landing.EIHListeners) != 1 {
		t.Fatal("upgraded relay/target did not receive additive EIH 24000 listeners")
	}
	if !slices.Contains(reloaded.nodes[relayCert].Desired.Landing.ClientListeners, relayListener) || !slices.Contains(reloaded.nodes[targetCert].Desired.Landing.ClientListeners, targetListener) {
		t.Fatal("additive EIH projection unexpectedly withdrew legacy 24001 listeners before cutover")
	}
	if _, err := reloaded.CutoverLegacyPooledRoute(context.Background(), v1Grant.ID); err == nil {
		t.Fatal("CutoverLegacyPooledRoute succeeded before relay/target reported applied EIH 24000 receipts")
	}
	reportFreshLanding(t, reloaded, relayCert, relayID)
	reportFreshLanding(t, reloaded, targetCert, targetID)
	if _, err := reloaded.CutoverLegacyPooledRoute(context.Background(), v1Grant.ID); err != nil {
		t.Fatalf("CutoverLegacyPooledRoute failed after receipts ready: %v", err)
	}
	// P1 #3: Right after cutover, entry MUST switch straight onto the live admitted
	// candidate (NEVER empty/blocked) while relay & target retain legacy 24001
	// listeners until entry confirms its applied RelayPool receipt.
	if len(reloaded.nodes[entryCert].Desired.Entry.RelayPools) != 1 || len(reloaded.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 1 {
		t.Fatalf("entry did not switch straight to live admitted candidate: %+v", reloaded.nodes[entryCert].Desired.Entry.RelayPools)
	}
	if !slices.Contains(reloaded.nodes[relayCert].Desired.Landing.ClientListeners, relayListener) || !slices.Contains(reloaded.nodes[targetCert].Desired.Landing.ClientListeners, targetListener) {
		t.Fatal("legacy 24001 listeners were withdrawn before cut-over entry confirmed applied receipt")
	}
	if !slices.Contains(reloaded.nodes[targetCert].Desired.Landing.UDPOverTCPListeners, chainID) {
		t.Fatal("legacy 24001 UDP-over-TCP grant was withdrawn before cut-over entry confirmed applied receipt")
	}
	if !reloaded.business.material.PooledRoutes[v1Grant.ID].RetiringLegacyTransport {
		t.Fatal("expected RetiringLegacyTransport=true until cut-over entry confirms receipt")
	}
	// P1 #1: Reloading the controller while RetiringLegacyTransport=true must succeed cleanly!
	reloaded2, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded2.LoadBusiness(keyPath); err != nil {
		t.Fatalf("LoadBusiness failed with RetiringLegacyTransport=true: %v", err)
	}
	reloaded = reloaded2
	// Once entry confirms its applied cut-over receipt via Exchange, the legacy
	// ServerTransport and 24001 listeners (including UDPOverTCPListeners) are automatically retired!
	reportFreshEntry(t, reloaded, entryCert)
	m3 := reloaded.business.material
	if _, stillLegacy := m3.ServerTransports[chainID]; stillLegacy {
		t.Fatal("legacy single-relay ServerTransport remained after cut-over entry receipt")
	}
	if _, keptTwoHop := m3.ServerTransports["twohop-keep"]; !keptTwoHop {
		t.Fatal("two-hop ServerTransport was lost during cutover")
	}
	if slices.Contains(reloaded.nodes[relayCert].Desired.Landing.ClientListeners, relayListener) || slices.Contains(reloaded.nodes[targetCert].Desired.Landing.ClientListeners, targetListener) || slices.Contains(reloaded.nodes[targetCert].Desired.Landing.UDPOverTCPListeners, chainID) {
		t.Fatal("legacy 24001 listeners or UDP grant remained after cut-over entry receipt")
	}
	if m3.PooledRoutes[v1Grant.ID].PendingLegacyCutover || m3.PooledRoutes[v1Grant.ID].RetiringLegacyTransport {
		t.Fatal("legacy cutover transition flags remained set after completion")
	}
	if len(reloaded.nodes[entryCert].Desired.Entry.RelayPools) != 1 || len(reloaded.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 1 {
		t.Fatalf("entry lost live admitted candidate after retiring legacy 24001 listeners: %+v", reloaded.nodes[entryCert].Desired.Entry.RelayPools)
	}
	if m3.ProtocolSecrets[routeCred.ID] != routeUUID || !reflect.DeepEqual(m3.TrafficCounters[routeCred.ID], v1Mat.TrafficCounters[routeCred.ID]) || !reflect.DeepEqual(m3.SubscriptionOrders, v1Mat.SubscriptionOrders) {
		t.Fatal("cutover altered UUID, traffic counters, or subscription order")
	}
	sub := getSubscription(t, reloaded, "/sub/example-token?format=mihomo", "Mihomo")
	if sub.Code != 200 || !strings.Contains(sub.Body.String(), "Issued HK Relay") || !strings.Contains(sub.Body.String(), routeUUID) {
		t.Fatalf("migrated subscription lost display name or UUID: code=%d body=%s", sub.Code, sub.Body.String())
	}

	// Historical v1 sealed snapshot remains readable via OpenImportMaterial.
	openedV1, err := glivela.OpenImportMaterial(v1Sealed, storageKey, s.business.snapshotID)
	if err != nil || openedV1.ServerTransportVersion != 1 || openedV1.ServerTransports[chainID].Peer.Relay == nil {
		t.Fatalf("old v1 snapshot not readable read-only: %v", err)
	}
}

func TestControlledSocketCutoverOptionAAndRollback(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }
	targetID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity

	// Grant existing direct route WITH UDP enabled over occupied 9.9.9.9:24000 socket
	// (tests P1 #2: two-hop-source with UDP during real Exchange in listener-pending!).
	grant.ID = "twohop-existing"
	grant.UDP = true
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal(err)
	}

	// Also enroll a second landing (landing-2) and a relay (relay-v4) so 9.9.9.9:24000 is
	// used BOTH as a pooled landing AND as a pooled relay ingress (P1 #3!).
	relayCert := strings.Repeat("c", 64)
	relayID := enrollPoolTestLanding(t, s, "relay-v4", relayCert, "100.64.0.21", "9.9.9.10", "8.8.8.8")
	landing2Cert := strings.Repeat("e", 64)
	landing2ID := enrollPoolTestLanding(t, s, "landing-2", landing2Cert, "100.64.0.23", "9.9.9.12", "8.8.8.8")
	obs := glivela.DefaultObservatoryConfig()
	if _, err := s.ChangeEntryRelayConfig(context.Background(), EntryRelayConfigChange{
		EntryID:          grant.EntryID,
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config:           glivela.EntryRelayConfig{SourceIPv4: "8.8.4.4", Observatory: &obs},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       "pool-v4",
			Name:     "IPv4 Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(1),
			Members:  []glivela.RelayPoolMember{{NodeID: "relay-v4", CertificateID: relayCert, IngressIPv4: "9.9.9.10", EgressIPv4: "8.8.8.8"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       "pool-via-target",
			Name:     "Via Target Relay Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(1),
			Members:  []glivela.RelayPoolMember{{NodeID: "landing-example", CertificateID: targetCert, IngressIPv4: "9.9.9.9", EgressIPv4: "8.8.8.8"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	pooled := grant
	pooled.ID = "pooled-on-occupied"
	pooled.UDP = false
	pooled.RelayPoolID = "pool-v4"
	pooled.LandingAddress = "9.9.9.9"
	pooled.ExpectedExit = "8.8.8.8"
	pooled.Name = "Pooled V4"
	pooled.ExpectedRevision = revision()

	// P1 #8: Both legacy v1 (MaxEntryRenderVersion=0) AND Docker EntryDriver
	// (MaxEntryRenderVersion=127, even with Desired.EntryRenderVersion==255!)
	// MUST be refused by ChangeRoute AND deferred by InspectSocketCutover.
	reportFreshLanding(t, s, targetCert, targetID)
	reportFreshLanding(t, s, relayCert, relayID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	if _, err := s.ChangeRoute(context.Background(), pooled); err == nil {
		t.Fatal("ChangeRoute accepted pooled route for entry with MaxEntryRenderVersion=0")
	}
	dockerObs := healthyEntryObservation(s.nodes[entryCert].Desired, time.Now().UTC())
	dockerObs.MaxEntryRenderVersion = 127
	for id, peer := range dockerObs.EntryHealth.Peers {
		peer.Status.LinkState = "authenticated"
		dockerObs.EntryHealth.Peers[id] = peer
	}
	if _, err := s.Exchange(context.Background(), entryCert, &dockerObs); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeRoute(context.Background(), pooled); err == nil {
		t.Fatal("ChangeRoute accepted pooled route for Docker EntryDriver (MaxEntryRenderVersion=127)")
	}
	oldPlan, err := s.InspectSocketCutover("landing-example", "9.9.9.9")
	if err != nil || !oldPlan.Deferred || !slices.Contains(oldPlan.BlockingConsumers, "entry-example") {
		t.Fatalf("expected cutover deferred for Docker EntryDriver even when Desired.EntryRenderVersion==255: %+v err=%v", oldPlan, err)
	}
	if _, err := s.StartSocketCutover(context.Background(), "landing-example", "9.9.9.9", s.nodes[targetCert].Desired.Revision); err == nil {
		t.Fatal("StartSocketCutover proceeded with Docker EntryDriver")
	}

	// Upgrade entry to NativeEntryDriver (MaxEntryRenderVersion=255) -> pooled route creation & cutover ready!
	reportFreshEntry(t, s, entryCert)
	if _, err := s.ChangeRoute(context.Background(), pooled); err != nil {
		t.Fatal(err)
	}
	pooledRelayIngress := pooled
	pooledRelayIngress.ID = "pooled-relay-ingress"
	pooledRelayIngress.EgressID = "landing-2"
	pooledRelayIngress.RelayPoolID = "pool-via-target"
	pooledRelayIngress.LandingAddress = "9.9.9.12"
	pooledRelayIngress.Name = "Pooled via Target Relay"
	pooledRelayIngress.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), pooledRelayIngress); err != nil {
		t.Fatal(err)
	}
	// Occupied single-user 9.9.9.9:24000 must NOT have been overwritten by projectRelayPools.
	if len(s.nodes[targetCert].Desired.Landing.EIHListeners) != 0 {
		t.Fatal("projectRelayPools collided with occupied single-user 24000 socket")
	}

	// InspectSocketCutover inventories ALL 3 consumer kinds
	// (two-hop-source, pooled-route-landing, AND pooled-route-relay)!
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	reportFreshEntry(t, s, entryCert)
	plan, err := s.InspectSocketCutover("landing-example", "9.9.9.9")
	if err != nil || !plan.Occupied || plan.Deferred || len(plan.Consumers) != 3 {
		t.Fatalf("expected ready cutover plan with 3 consumers (two-hop + landing + relay-ingress), got %+v err=%v", plan, err)
	}

	// Subtest A: Stage 1 + REAL Exchange during listener-pending (UDP two-hop-source!) + Targeted Rollback + receipt-gated cleanup.
	origTargetRev := s.nodes[targetCert].Desired.Revision
	started, err := s.StartSocketCutover(context.Background(), "landing-example", "9.9.9.9", origTargetRev)
	if err != nil || started.Phase != "listener-pending" || started.ListenerRevision != origTargetRev+1 {
		t.Fatalf("StartSocketCutover failed: %+v err=%v", started, err)
	}
	// P1 #2 regression: REAL Exchange by target AND entry during listener-pending must succeed without deadlock!
	if _, err := s.Exchange(context.Background(), targetCert, nil); err != nil {
		t.Fatalf("target Exchange deadlocked during listener-pending with UDP two-hop-source: %v", err)
	}
	if _, err := s.Exchange(context.Background(), entryCert, nil); err != nil {
		t.Fatalf("entry Exchange deadlocked during listener-pending: %v", err)
	}
	// P2 #2 regression: UpdateAccountPlan & ResetAccountUsage during listener-pending must NOT bump cutover target revision!
	if _, err := s.UpdateAccountPlan(context.Background(), grant.AccountID, revision(), s.business.material.Plan.Accounts[0].Account.Plan); err != nil {
		t.Fatalf("UpdateAccountPlan failed during listener-pending: %v", err)
	}
	if s.nodes[targetCert].Desired.Revision != started.ListenerRevision {
		t.Fatal("UpdateAccountPlan clobbered listener-pending cutover target revision")
	}
	if _, err := s.AdvanceSocketCutover(context.Background(), started.ID); err == nil {
		t.Fatal("AdvanceSocketCutover succeeded before listener EIH receipt")
	}
	// P1 #5 & P2 #1: Mutate an unrelated account revision AND disable UDP during
	// listener-pending, then roll back; rollback must preserve concurrent changes,
	// project current live UDP=false directly, and clear cleanly even after a
	// subsequent legitimate revision bump on target!
	if _, err := s.ResetAccountUsage(context.Background(), grant.AccountID, revision()); err != nil {
		t.Fatalf("ResetAccountUsage during cutover failed: %v", err)
	}
	grant.UDP = false
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("disable UDP during listener-pending before rollback failed: %v", err)
	}
	revAfterReset := revision()
	rolled, err := s.RollbackSocketCutover(context.Background(), started.ID)
	if err != nil || !rolled.RolledBack || rolled.Phase != "rollback-pending" || rolled.ListenerRevision <= started.ListenerRevision {
		t.Fatalf("RollbackSocketCutover failed or non-monotonic revision: %+v err=%v", rolled, err)
	}
	if revision() != revAfterReset {
		t.Fatal("targeted rollback clobbered concurrent account revision")
	}
	if s.nodes[targetCert].Desired.Landing.Sources[0].UDPOverTCP {
		t.Fatal("rollback restored stale UDPOverTCP=true instead of projecting live UDP=false")
	}
	// Legitimate post-rollback target change on an unrelated unoccupied socket bumps
	// target revision above RollbackListener.Revision; reporting the new exact receipt
	// MUST still complete rollback (not wedge!).
	pooledBump := pooled
	pooledBump.ID = "pooled-v4-bump"
	pooledBump.LandingAddress = "9.9.9.19"
	pooledBump.Name = "Pooled Bump"
	pooledBump.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), pooledBump); err != nil {
		t.Fatalf("unrelated pooled change during rollback-pending failed: %v", err)
	}
	if s.nodes[targetCert].Desired.Revision <= rolled.ListenerRevision {
		t.Fatal("unrelated pooled change did not advance target revision above RollbackListener.Revision")
	}
	// P1 #4: Cutover record MUST remain persisted in rollback-pending until target confirms rollback receipt!
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.path), socketCutoversFile)); err != nil {
		t.Fatal("socket-cutovers.json was removed before rollback receipt confirmation")
	}
	reportFreshLanding(t, s, targetCert, targetID)
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.path), socketCutoversFile)); !os.IsNotExist(err) {
		t.Fatal("socket-cutovers.json did not auto-clear after rollback receipt confirmation")
	}
	if slices.ContainsFunc(s.nodes[targetCert].Desired.Landing.EIHListeners, func(l landing.EIHListener) bool { return l.Address == "9.9.9.9" }) || !socketOccupiedBySingleUser(*s.nodes[targetCert].Desired.Landing, "9.9.9.9") {
		t.Fatal("RollbackSocketCutover did not restore pre-cutover single-user socket")
	}
	pooledBump.Enabled = false
	pooledBump.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), pooledBump); err != nil {
		t.Fatal(err)
	}
	reportFreshLanding(t, s, targetCert, targetID)
	reportFreshLanding(t, s, relayCert, relayID)
	reportFreshEntry(t, s, entryCert)
	grant.UDP = true
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("re-enable UDP after rollback completion failed: %v", err)
	}
	reportFreshLanding(t, s, targetCert, targetID)

	// Subtest B: Full Stage 1 -> mid-cutover UDP revocation (P1 #7!) -> updated listener receipt -> Stage 2 -> final receipts -> complete.
	reportFreshEntry(t, s, entryCert)
	started, err = s.StartSocketCutover(context.Background(), "landing-example", "9.9.9.9", s.nodes[targetCert].Desired.Revision)
	if err != nil || started.Phase != "listener-pending" {
		t.Fatalf("second StartSocketCutover failed: %+v err=%v", started, err)
	}
	// P1 #7: Revoking UDP DURING listener-pending MUST immediately clear UDP on the
	// landing EIH user and require the new revision's exact receipt before advancing!
	staleRev, staleSHA := s.nodes[targetCert].Desired.Revision, s.nodes[targetCert].Desired.ConfigSHA256
	grant.UDP = false
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("revoke UDP during listener-pending failed: %v", err)
	}
	if s.nodes[targetCert].Desired.Revision <= staleRev || s.nodes[targetCert].Desired.Landing.EIHListeners[0].Users[0].UDP {
		t.Fatal("revoking UDP during listener-pending did not immediately revoke landing EIH UDP")
	}
	// Submitting a stale receipt for the pre-revocation revision MUST NOT unlock Stage 2!
	if _, err := s.Exchange(context.Background(), targetCert, &Observation{
		AppliedReceipt:          glivela.AppliedReceipt{Revision: staleRev, ConfigSHA256: staleSHA, RuntimeReady: true},
		MaxLandingRenderVersion: landing.RenderVersion,
		ManagementIdentity:      &targetID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdvanceSocketCutover(context.Background(), started.ID); err == nil {
		t.Fatal("AdvanceSocketCutover advanced on stale pre-revocation listener receipt")
	}
	reportFreshLanding(t, s, targetCert, targetID)

	stage2, err := s.AdvanceSocketCutover(context.Background(), started.ID)
	if err != nil || stage2.Phase != "entries-pending" || !slices.Contains(stage2.PendingEntries, "entry-example") {
		t.Fatalf("AdvanceSocketCutover Stage 2 failed: %+v err=%v", stage2, err)
	}
	if !strings.Contains(s.nodes[entryCert].Desired.Entry.Peers[0].Transport.Key, ":") {
		t.Fatal("two-hop consumer was not switched to EIH <iPSK>:<uPSK>")
	}
	// P1 #3 regression: Even if entry reports its Stage-2 receipt BEFORE target applies the
	// newly projected pooled EIH users (and before entry admits pooled candidates!), cutover MUST NOT complete!
	reportFreshEntry(t, s, entryCert)
	if _, err := s.AdvanceSocketCutover(context.Background(), started.ID); err == nil {
		t.Fatal("AdvanceSocketCutover reported completed before final listener & pooled admission receipts")
	}

	// Now relay, target landing, and landing-2 apply their updated EIH revisions -> Exchange admits pooled candidates -> entry applies final revision!
	reportFreshLanding(t, s, relayCert, relayID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	reportFreshLanding(t, s, targetCert, targetID)
	reportFreshEntry(t, s, entryCert)
	done, err := s.AdvanceSocketCutover(context.Background(), started.ID)
	if err != nil || !done.Completed || done.Phase != "completed" {
		t.Fatalf("AdvanceSocketCutover completion failed after all receipts ready: %+v err=%v", done, err)
	}

	// Cut-over two-hop peer stays valid for both publicPeerAcceptance and subscription authorization.
	entry := s.nodes[entryCert]
	if _, err := s.publicPeerAcceptance(entryCert, landingAcceptanceRequest{
		SnapshotID:   entry.ID,
		PeerID:       "landing-example",
		Revision:     entry.Desired.Revision,
		ConfigSHA256: entry.Desired.ConfigSHA256,
	}); err != nil {
		t.Fatalf("publicPeerAcceptance failed for cut-over two-hop EIH peer: %v", err)
	}
	s.mu.Lock()
	authOK := s.subscriptionPeerAuthorized(s.nodes[entryCert], "landing-example", time.Now().UTC())
	s.mu.Unlock()
	if !authOK {
		t.Fatal("subscriptionPeerAuthorized rejected cut-over two-hop EIH peer")
	}

	// P1 #7 regression: Re-enabling UDP, revoking UDP, disabling, and deleting the cut-over
	// two-hop grant must toggle its landing EIH UDP flag, withdraw its landing EIH user, and
	// GC its uPSK after receipts!
	var twoHopCredID string
	for _, b := range s.business.material.TwoHopEIHBindings {
		twoHopCredID = b.CredentialID
	}
	if twoHopCredID == "" {
		t.Fatal("missing TwoHopEIHBinding after cutover")
	}
	grant.UDP = true
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("re-enable UDP on cut-over two-hop grant failed: %v", err)
	}
	udpEnabled := false
	for _, u := range s.nodes[targetCert].Desired.Landing.EIHListeners[0].Users {
		if u.ID == twoHopCredID && u.UDP {
			udpEnabled = true
		}
	}
	if !udpEnabled {
		t.Fatal("re-enabling UDP on cut-over two-hop grant did not enable landing EIH UDP")
	}
	grant.UDP = false
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("revoke UDP on cut-over two-hop grant failed: %v", err)
	}
	for _, u := range s.nodes[targetCert].Desired.Landing.EIHListeners[0].Users {
		if u.ID == twoHopCredID && u.UDP {
			t.Fatal("cut-over two-hop landing EIH user retained UDP after UDP was disabled")
		}
	}
	grant.Enabled = false
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("disable cut-over two-hop grant failed: %v", err)
	}
	for _, u := range s.nodes[targetCert].Desired.Landing.EIHListeners[0].Users {
		if u.ID == twoHopCredID {
			t.Fatal("disabled cut-over two-hop grant retained its landing EIH uPSK")
		}
	}
	// P2 #2: Deleting the disabled cut-over grant while landing is offline retains
	// TwoHopEIHBinding until landing returns online and confirms revocation via Exchange!
	s.mu.Lock()
	tn := s.nodes[targetCert]
	tn.ReportedAt = time.Now().UTC().Add(-24 * time.Hour)
	s.nodes[targetCert] = tn
	s.mu.Unlock()
	reportFreshEntry(t, s, entryCert)
	grant.Delete = true
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatalf("delete cut-over two-hop grant while landing offline failed: %v", err)
	}
	if len(s.business.material.TwoHopEIHBindings) == 0 {
		t.Fatal("TwoHopEIHBinding pruned before offline landing confirmed revocation receipt")
	}
	reportFreshLanding(t, s, targetCert, targetID)
	if len(s.business.material.TwoHopEIHBindings) != 0 || s.business.material.RelayPoolCredentials[twoHopCredID] != "" {
		t.Fatal("delayed landing revocation receipt did not auto-prune TwoHopEIHBinding and GC its uPSK")
	}
}

func TestSocketCutoverTwoHopTransportExchangeAndCrashRecovery(t *testing.T) {
	// Exercises P1 #2 (two-hop-transport ServerTransport on port 24000 during real Exchange)
	// AND P1 #4 (crash injection at EVERY write boundary followed by OpenStore+LoadBusiness recovery!).
	boundaries := []string{
		"start-after-intent",
		"start-after-business",
		"start-after-nodes",
		"advance-after-intent",
		"advance-after-business",
		"rollback-after-intent",
		"rollback-after-nodes",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			s, entryCert, targetCert, grant := managedServerLandingFixture(t)
			revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }
			targetID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity

			// Enroll a two-hop ServerTransport bound to port 24000 on IPv6 2606:4700:4700::1111.
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
			entry := s.nodes[entryCert]
			plan := *entry.Desired.clone().Entry
			plan.Revision++
			plan.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: "2606:4700:4700::1111", Port: 24000, ClientListenerID: "twohop-24000"}
			plan.Peers[0].Port = 24000
			var err error
			entry.Desired, err = NewEntryDesired(plan, *entry.Desired.EntryNetwork)
			if err != nil {
				t.Fatal(err)
			}
			resource := glivela.ServerTransport{
				ID: "twohop-24000", Name: "TwoHop 24000", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID,
				EntryCertificateID: entryCert, LandingCertificateID: targetCert,
				Peer:         plan.Peers[0],
				ExpectedExit: entry.Desired.EntryNetwork.Peers[0].ExpectedExit,
				Listener:     glivela.TransportListener{ID: "twohop-24000", Port: 24000, Key: key, Source: "2001:4860:4860::8888", Transport: "ipv6-ss2022", Address: "2606:4700:4700::1111", EgressIP: "8.8.8.8"},
			}
			enrollFixtureServerTransport(t, s, entry, resource)
			reportFreshLanding(t, s, targetCert, targetID)
			grant.ExpectedRevision = revision()
			if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
				t.Fatal(err)
			}
			reportFreshLanding(t, s, targetCert, targetID)
			reportFreshEntry(t, s, entryCert)

			keyPath := filepath.Join(filepath.Dir(s.path), "business.key")
			injected := errors.New("simulated crash at " + boundary)
			s.cutoverFaultHook = func(step string) error {
				if step == boundary {
					return injected
				}
				return nil
			}

			switch {
			case strings.HasPrefix(boundary, "start-"):
				if _, err := s.StartSocketCutover(context.Background(), "landing-example", "2606:4700:4700::1111", s.nodes[targetCert].Desired.Revision); !errors.Is(err, injected) {
					t.Fatalf("expected injected crash at %s, got %v", boundary, err)
				}
				reloaded, err := OpenStore(s.path)
				if err != nil {
					t.Fatal(err)
				}
				if err := reloaded.LoadBusiness(keyPath); err != nil {
					t.Fatalf("startup recovery after %s failed: %v", boundary, err)
				}
				// Real Exchange on target during listener-pending must succeed for two-hop-transport!
				if _, err := reloaded.Exchange(context.Background(), targetCert, nil); err != nil {
					t.Fatalf("target Exchange failed after %s recovery: %v", boundary, err)
				}
				reportFreshLanding(t, reloaded, targetCert, targetID)
				if _, err := reloaded.AdvanceSocketCutover(context.Background(), socketCutoverID("landing-example", "2606:4700:4700::1111")); err != nil {
					t.Fatalf("AdvanceSocketCutover after %s recovery failed: %v", boundary, err)
				}

			case strings.HasPrefix(boundary, "advance-"):
				s.cutoverFaultHook = nil
				started, err := s.StartSocketCutover(context.Background(), "landing-example", "2606:4700:4700::1111", s.nodes[targetCert].Desired.Revision)
				if err != nil {
					t.Fatal(err)
				}
				reportFreshLanding(t, s, targetCert, targetID)
				s.cutoverFaultHook = func(step string) error {
					if step == boundary {
						return injected
					}
					return nil
				}
				if _, err := s.AdvanceSocketCutover(context.Background(), started.ID); !errors.Is(err, injected) {
					t.Fatalf("expected injected crash at %s, got %v", boundary, err)
				}
				if boundary == "advance-after-intent" {
					// P1 #4: Online in-process retry of AdvanceSocketCutover while Phase=="entries-applying"
					// MUST replay Stage 2 and switch entry to EIH instead of completing on the old pre-EIH receipt!
					s.cutoverFaultHook = nil
					retried, err := s.AdvanceSocketCutover(context.Background(), started.ID)
					if err != nil || retried.Completed || retried.Phase != "entries-pending" {
						t.Fatalf("online retry after advance-after-intent did not replay Stage 2: %+v err=%v", retried, err)
					}
					if !strings.Contains(s.nodes[entryCert].Desired.Entry.Peers[0].Transport.Key, ":") {
						t.Fatal("online retry after advance-after-intent left entry on single-user key")
					}
					reportFreshEntry(t, s, entryCert)
					if done, err := s.AdvanceSocketCutover(context.Background(), started.ID); err != nil || !done.Completed {
						t.Fatalf("completion after online advance retry failed: %+v err=%v", done, err)
					}
					return
				}
				reloaded, err := OpenStore(s.path)
				if err != nil {
					t.Fatal(err)
				}
				if err := reloaded.LoadBusiness(keyPath); err != nil {
					t.Fatalf("startup recovery after %s failed: %v", boundary, err)
				}
				if !strings.Contains(reloaded.nodes[entryCert].Desired.Entry.Peers[0].Transport.Key, ":") {
					t.Fatalf("recovery after %s did not finish switching entry peer to EIH", boundary)
				}
				reportFreshEntry(t, reloaded, entryCert)
				if done, err := reloaded.AdvanceSocketCutover(context.Background(), started.ID); err != nil || !done.Completed {
					t.Fatalf("completion after %s recovery failed: %+v err=%v", boundary, done, err)
				}

			case strings.HasPrefix(boundary, "rollback-"):
				s.cutoverFaultHook = nil
				started, err := s.StartSocketCutover(context.Background(), "landing-example", "2606:4700:4700::1111", s.nodes[targetCert].Desired.Revision)
				if err != nil {
					t.Fatal(err)
				}
				if boundary == "rollback-after-nodes" {
					// Advance to entries-pending first so BOTH target AND entry are affected
					// by rollback (tests P1 #6: crash after nodes.json commit must NOT lose
					// entry-example from required rollback receipts!).
					reportFreshLanding(t, s, targetCert, targetID)
					if _, err := s.AdvanceSocketCutover(context.Background(), started.ID); err != nil {
						t.Fatal(err)
					}
				}
				s.cutoverFaultHook = func(step string) error {
					if step == boundary {
						return injected
					}
					return nil
				}
				if _, err := s.RollbackSocketCutover(context.Background(), started.ID); !errors.Is(err, injected) {
					t.Fatalf("expected injected crash at %s, got %v", boundary, err)
				}
				if boundary == "rollback-after-intent" {
					// P1 #6: Direct retry of RollbackSocketCutover while Phase=="rollback-applying"
					// must execute the rollback (NOT falsely treat empty receipts as rolled-back!).
					s.cutoverFaultHook = nil
					retried, err := s.RollbackSocketCutover(context.Background(), started.ID)
					if err != nil || retried.Phase != "rollback-pending" || len(s.nodes[targetCert].Desired.Landing.EIHListeners) != 0 {
						t.Fatalf("rollback retry after rollback-after-intent failed: %+v err=%v", retried, err)
					}
					reportFreshLanding(t, s, targetCert, targetID)
					if _, err := os.Stat(filepath.Join(filepath.Dir(s.path), socketCutoversFile)); !os.IsNotExist(err) {
						t.Fatal("rollback cutover file not cleared after retry and target receipt")
					}
					return
				}
				reloaded, err := OpenStore(s.path)
				if err != nil {
					t.Fatal(err)
				}
				if err := reloaded.LoadBusiness(keyPath); err != nil {
					t.Fatalf("startup recovery after %s failed: %v", boundary, err)
				}
				if len(reloaded.nodes[targetCert].Desired.Landing.EIHListeners) != 0 || len(reloaded.business.material.TwoHopEIHBindings) != 0 {
					t.Fatalf("recovery after %s left partial EIH state behind", boundary)
				}
				if strings.Contains(reloaded.nodes[entryCert].Desired.Entry.Peers[0].Transport.Key, ":") {
					t.Fatalf("recovery after %s did not restore entry single-user key", boundary)
				}
				// Report ONLY target receipt first: cutover MUST stay in rollback-pending
				// waiting for entry-example to apply its rolled-back single-user peer!
				reportFreshLanding(t, reloaded, targetCert, targetID)
				if _, err := os.Stat(filepath.Join(filepath.Dir(s.path), socketCutoversFile)); err != nil {
					t.Fatalf("rollback cutover file cleared prematurely before entry-example applied rollback receipt after %s", boundary)
				}
				reportFreshEntry(t, reloaded, entryCert)
				if _, err := os.Stat(filepath.Join(filepath.Dir(s.path), socketCutoversFile)); !os.IsNotExist(err) {
					t.Fatalf("rollback cutover file not cleaned after %s recovery and both receipts", boundary)
				}
			}
		})
	}
}

func TestObservatoryLowFrequencyReportingAndCoalescing(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }
	relayCert := strings.Repeat("c", 64)
	relayID := enrollPoolTestLanding(t, s, "relay-obs", relayCert, "100.64.0.21", "9.9.9.10", "2001:4860:4860::1111")
	targetID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	reportFreshEntry(t, s, entryCert)

	obsCfg := glivela.DefaultObservatoryConfig()
	if _, err := s.ChangeEntryRelayConfig(context.Background(), EntryRelayConfigChange{
		EntryID:          grant.EntryID,
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config:           glivela.EntryRelayConfig{SourceIPv6: "2001:4860:4860::8888", Observatory: &obsCfg},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeRelayPool(context.Background(), RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       "pool-obs",
			Name:     "Obs Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(1),
			Members:  []glivela.RelayPoolMember{{NodeID: "relay-obs", CertificateID: relayCert, IngressIPv6: "2001:4860:4860::1111", EgressIPv6: "2001:4860:4860::1111"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	grant.ID = "route-obs"
	grant.RelayPoolID = "pool-obs"
	grant.LandingAddress = "2606:4700:4700::1111"
	grant.ExpectedExit = "8.8.8.8"
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	reportFreshLanding(t, s, relayCert, relayID)
	reportFreshLanding(t, s, targetCert, targetID)

	entry := s.nodes[entryCert]
	candTag := glivela.PoolCandidateTag(entry.Desired.Entry.RelayPools[0].Key, 0)

	// 1. P2 #4: Consecutive failures MUST also respect the 15s throttle; worker restart re-queries immediately.
	failCalls := 0
	driver := &NativeEntryDriver{
		SystemdDriver: SystemdDriver{Role: "entry", WorkerUID: 990, WorkerGID: 990, Unit: "glivela-entry.service", WorkerUser: "glivela", Interface: "tailscale0"},
		Directory:     t.TempDir(),
	}
	driver.observatory.queryFn = func(_ context.Context, _ string) (map[string]landing.ObservatoryOutboundStatus, error) {
		failCalls++
		return nil, errors.New("api unreachable")
	}
	proc := nativeEntryProcess{Active: true, PID: 1000, Invocation: "inv-fail", StartedAt: "90"}
	if rep := driver.observatoryFromProcess(context.Background(), entry.Desired, proc); rep != nil {
		t.Fatalf("expected nil report on query error, got %+v", rep)
	}
	if rep := driver.observatoryFromProcess(context.Background(), entry.Desired, proc); rep != nil {
		t.Fatalf("expected nil report on throttled retry, got %+v", rep)
	}
	if failCalls != 1 {
		t.Fatalf("observatory error bypassed 15s throttle: failCalls=%d", failCalls)
	}

	// 2. Worker generation change re-queries immediately and caches success for 15s.
	calls := 0
	driver.observatory.queryFn = func(_ context.Context, _ string) (map[string]landing.ObservatoryOutboundStatus, error) {
		calls++
		return map[string]landing.ObservatoryOutboundStatus{
			candTag: {
				OutboundTag: candTag,
				Alive:       true,
				DelayMS:     42,
				HealthPing: &landing.ObservatoryHealthPing{
					All:     3,
					Fail:    0,
					Average: 40 * time.Millisecond,
					Min:     35 * time.Millisecond,
					Max:     48 * time.Millisecond,
				},
			},
		}, nil
	}
	proc = nativeEntryProcess{Active: true, PID: 1001, Invocation: "inv-1", StartedAt: "100"}
	rep1 := driver.observatoryFromProcess(context.Background(), entry.Desired, proc)
	rep2 := driver.observatoryFromProcess(context.Background(), entry.Desired, proc)
	if calls != 1 || rep1 == nil || rep2 == nil || len(rep1.Paths) != 1 || rep1.Paths[0].DelayMS != 42 {
		t.Fatalf("expected 1 throttled observatory query, got calls=%d rep=%+v", calls, rep1)
	}
	proc.PID = 1002
	_ = driver.observatoryFromProcess(context.Background(), entry.Desired, proc)
	if calls != 2 {
		t.Fatalf("expected worker generation change to re-query observatory, calls=%d", calls)
	}

	// 3. Store.Exchange accepts valid Observatory, exposes it in Business(), preserves revision & coalescing.
	s.mu.Lock()
	s.nodesFlushInterval = time.Hour
	s.mu.Unlock()
	t1 := time.Now().UTC().Add(-2 * time.Second)
	obs := healthyEntryObservation(entry.Desired, t1)
	obs.MaxEntryRenderVersion = glivela.XrayRenderVersion
	for id, peer := range obs.EntryHealth.Peers {
		peer.Status.LinkState = "authenticated"
		obs.EntryHealth.Peers[id] = peer
	}
	obs.Observatory = rep1
	if _, err := s.Exchange(context.Background(), entryCert, &obs); err != nil {
		t.Fatal(err)
	}
	if s.nodes[entryCert].Desired.Revision != entry.Desired.Revision {
		t.Fatal("Observatory telemetry unexpectedly bumped entry revision")
	}
	inv := s.Business()
	if len(inv.ObservatoryPaths) != 1 || inv.ObservatoryPaths[0].RelayNodeID != "relay-obs" || inv.ObservatoryPaths[0].DelayMS != 42 || !inv.ObservatoryPaths[0].Alive {
		t.Fatalf("Business inventory missing ObservatoryPaths: %+v", inv.ObservatoryPaths)
	}
	t2 := t1.Add(time.Second)
	obs2 := obs.clone()
	obs2.EntryHealth.SampledAt = t2
	for id, peer := range obs2.EntryHealth.Peers {
		peer.Status.CheckedAt = t2
		peer.Status.LastHealthyAt = t2
		obs2.EntryHealth.Peers[id] = peer
	}
	repUpdated := rep1.clone()
	repUpdated.SampledAt = t2
	repUpdated.Paths[0].DelayMS = 55
	obs2.Observatory = repUpdated
	if _, err := s.Exchange(context.Background(), entryCert, &obs2); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	dirty := s.nodesDirty
	s.mu.Unlock()
	if !dirty {
		t.Fatal("steady-state Observatory update broke nodes.json heartbeat coalescing")
	}

	// 4. Malformed / future Observatory is discarded cleanly without failing Exchange or RuntimeReady.
	t3 := t2.Add(500 * time.Millisecond)
	badObs := obs2.clone()
	badObs.EntryHealth.SampledAt = t3
	for id, peer := range badObs.EntryHealth.Peers {
		peer.Status.CheckedAt = t3
		peer.Status.LastHealthyAt = t3
		badObs.EntryHealth.Peers[id] = peer
	}
	badObs.Observatory = &EntryObservatoryReport{
		SampledAt: time.Now().UTC().Add(time.Hour),
		Paths:     []ObservatoryPathStatus{{PoolID: "pool-obs", RelayNodeID: "relay-obs", EgressID: "landing-example", OutboundTag: "unknown-tag", Alive: true, DelayMS: 10}},
	}
	if _, err := s.Exchange(context.Background(), entryCert, &badObs); err != nil {
		t.Fatalf("malformed Observatory should not fail Exchange: %v", err)
	}
	if s.nodes[entryCert].Receipt == nil || !s.nodes[entryCert].Receipt.RuntimeReady || s.nodes[entryCert].Receipt.Observatory != nil {
		t.Fatal("malformed Observatory was not discarded cleanly")
	}
}

func TestRelayPoolAdminEndpointsAndDockerDriverRejection(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	serverIdentity, _, _ := identity(t, ca, key, true)
	adminIdentity, adminCert, _ := identity(t, ca, key, false)
	nodeIdentity, _, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	s, entryCert, _, _ := managedServerLandingFixture(t)
	relayCert := strings.Repeat("c", 64)
	enrollPoolTestLanding(t, s, "relay-admin", relayCert, "100.64.0.21", "9.9.9.10", "2001:4860:4860::1111")

	server, err := NewServer("127.0.0.1:0", s, serverIdentity, roots, []string{CertificateID(adminCert)})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server.Handler)
	listener.EnableHTTP2 = true
	listener.TLS = server.TLSConfig.Clone()
	listener.Config.HTTP2 = server.HTTP2
	listener.StartTLS()
	defer listener.Close()

	mkClient := func(cert tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}
	}
	adminHTTP, nodeHTTP := mkClient(adminIdentity), mkClient(nodeIdentity)
	post := func(c *http.Client, path string, body any, want int) []byte {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Post(listener.URL+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s: status %d want %d body=%s", path, resp.StatusCode, want, buf.String())
		}
		return buf.Bytes()
	}

	for _, ep := range []string{"/v1/admin/relay-pools", "/v1/admin/entry-observatory", "/v1/admin/socket-cutover"} {
		post(nodeHTTP, ep, map[string]any{}, http.StatusForbidden)
	}

	obs := glivela.DefaultObservatoryConfig()
	post(adminHTTP, "/v1/admin/entry-observatory", EntryRelayConfigChange{
		EntryID:          "entry-example",
		ExpectedRevision: s.nodes[entryCert].Desired.Revision,
		Config:           glivela.EntryRelayConfig{SourceIPv6: "2001:4860:4860::8888", Observatory: &obs},
	}, http.StatusAccepted)

	poolRaw := post(adminHTTP, "/v1/admin/relay-pools", RelayPoolChange{
		Pool: glivela.RelayPool{
			ID:       "pool-admin",
			Name:     "Admin Pool",
			Strategy: glivela.DefaultRelayPoolStrategy(1),
			Members:  []glivela.RelayPoolMember{{NodeID: "relay-admin", CertificateID: relayCert, IngressIPv6: "2001:4860:4860::1111", EgressIPv6: "2001:4860:4860::1111"}},
		},
	}, http.StatusAccepted)
	var poolRes RelayPoolChangeResult
	if err := json.Unmarshal(poolRaw, &poolRes); err != nil || poolRes.PoolID != "pool-admin" || poolRes.Revision != 1 {
		t.Fatalf("unexpected relay-pools response: %s %v", string(poolRaw), err)
	}

	inspectRaw := post(adminHTTP, "/v1/admin/socket-cutover", SocketCutoverRequest{
		Action:       "inspect",
		TargetNodeID: "landing-example",
		Address:      "9.9.9.9",
	}, http.StatusOK)
	var cutPlan SocketCutoverPlan
	if err := json.Unmarshal(inspectRaw, &cutPlan); err != nil || !cutPlan.Occupied {
		t.Fatalf("unexpected socket-cutover inspect response: %s %v", string(inspectRaw), err)
	}

	// Legacy Docker EntryDriver must refuse entry plans with RelayPools.
	dockerDir := t.TempDir()
	cfgDir := t.TempDir()
	dockerDriver := &EntryDriver{
		Directory: dockerDir,
		Container: EntryContainer{
			ApplicationID:          "entry-example",
			ContainerID:            strings.Repeat("a", 64),
			ImageID:                "sha256:" + strings.Repeat("b", 64),
			ConfigurationDirectory: cfgDir,
			NetworkID:              strings.Repeat("c", 64),
			NetworkName:            "bridge-example",
			Bridge:                 "br-example",
			NetworkAddress:         "172.20.0.2",
			UID:                    1000,
			GID:                    0,
		},
	}
	entryPlan := *s.nodes[entryCert].Desired.clone().Entry
	entryPlan.Peers = nil
	entryPlan.RelayEdges = []glivela.EntryRelayEdge{{ID: "re-1", RelayNodeID: "relay-admin", Source: "2001:4860:4860::8888", Address: "2001:4860:4860::1111", Port: glivela.RelayPoolPort, Key: "MDEyMzQ1Njc4OWFiY2RlZg==:YWJjZGVmZ2hpamtsbW5vcA=="}}
	entryNet := EntryNetwork{
		RelayPeers: []EntryRelayNetworkPeer{{
			NodeID:        "relay-admin",
			CertificateID: relayCert,
			Identity:      landing.PeerIdentity{ID: "relay-admin-mesh", PublicKey: "nodekey:relay-admin", Address: "100.64.0.21"},
		}},
	}
	entryDesired, err := NewEntryDesired(entryPlan, entryNet)
	if err != nil {
		t.Fatal(err)
	}
	if err := dockerDriver.plan(entryDesired); err == nil || !strings.Contains(err.Error(), "relay pools require the native entry runtime") {
		t.Fatalf("Docker EntryDriver did not refuse RelayEdges: %v", err)
	}
}

func TestSocketCutoverTargetedRollbackPreservesConcurrentCutoverAndGrants(t *testing.T) {
	s, entryCert, target1Cert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }
	target1ID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity

	// Enroll a second landing whose port 24000 is ALSO occupied by a two-hop
	// ServerTransport from the SAME entry-example node.
	target2Cert := strings.Repeat("e", 64)
	target2ID := enrollPoolTestLanding(t, s, "landing-2", target2Cert, "100.64.0.23", "9.9.9.12", "8.8.8.8")
	key2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 16))
	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	network := entry.Desired.EntryNetwork.clone()
	peer2 := plan.Peers[0]
	peer2.EgressID = "landing-2"
	peer2.Address = "100.64.0.23"
	peer2.Port = 24000
	peer2.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key2, PublicAddress: "2606:4700:4700::2222", Port: 24000, ClientListenerID: "twohop-l2-24000"}
	plan.Peers = append(plan.Peers, peer2)
	npeer2 := EntryPeer{EgressID: "landing-2", Identity: target2ID, Target: network.Peers[0].Target, ExpectedExit: "8.8.8.8"}
	network.Peers = append(network.Peers, npeer2)
	plan.Revision++
	var err error
	entry.Desired, err = NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal(err)
	}
	res2 := glivela.ServerTransport{
		ID: "twohop-l2-24000", Name: "TwoHop L2 24000", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: "landing-2",
		EntryCertificateID: entryCert, LandingCertificateID: target2Cert,
		Peer:         peer2,
		ExpectedExit: "8.8.8.8",
		Listener:     glivela.TransportListener{ID: "twohop-l2-24000", Port: 24000, Key: key2, Source: "2001:4860:4860::8888", Transport: "ipv6-ss2022", Address: "2606:4700:4700::2222", EgressIP: "8.8.8.8"},
	}
	enrollFixtureServerTransport(t, s, entry, res2)

	// Add an active grant on landing-1 AND a second active grant on landing-2.
	g1 := grant
	g1.ID = "grant-l1"
	g1.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g1); err != nil {
		t.Fatal(err)
	}
	g2 := grant
	g2.ID = "grant-l2"
	g2.EgressID = "landing-2"
	g2.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g2); err != nil {
		t.Fatal(err)
	}
	reportFreshLanding(t, s, target1Cert, target1ID)
	reportFreshLanding(t, s, target2Cert, target2ID)
	reportFreshEntry(t, s, entryCert)

	// Start & advance cutover #2 (landing-2) so entry switches landing-2's peer to EIH.
	cut2, err := s.StartSocketCutover(context.Background(), "landing-2", "2606:4700:4700::2222", s.nodes[target2Cert].Desired.Revision)
	if err != nil {
		t.Fatalf("StartSocketCutover(landing-2): %v", err)
	}
	reportFreshLanding(t, s, target2Cert, target2ID)
	if _, err := s.AdvanceSocketCutover(context.Background(), cut2.ID); err != nil {
		t.Fatalf("AdvanceSocketCutover(landing-2): %v", err)
	}
	var l2EIHKey string
	for _, p := range s.nodes[entryCert].Desired.Entry.Peers {
		if p.EgressID == "landing-2" {
			l2EIHKey = p.Transport.Key
		}
	}
	if !strings.Contains(l2EIHKey, ":") {
		t.Fatalf("landing-2 peer did not switch to EIH: %q", l2EIHKey)
	}

	// Concurrently start & advance cutover #1 (landing-example), then disable grant-l2
	// on the shared entry BEFORE rolling back cutover #1.
	reportFreshEntry(t, s, entryCert)
	cut1, err := s.StartSocketCutover(context.Background(), "landing-example", "9.9.9.9", s.nodes[target1Cert].Desired.Revision)
	if err != nil {
		t.Fatalf("StartSocketCutover(landing-example): %v", err)
	}
	reportFreshLanding(t, s, target1Cert, target1ID)
	if _, err := s.AdvanceSocketCutover(context.Background(), cut1.ID); err != nil {
		t.Fatalf("AdvanceSocketCutover(landing-example): %v", err)
	}
	g2.Enabled = false
	g2.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), g2); err != nil {
		t.Fatalf("concurrent disable grant-l2 failed: %v", err)
	}

	// Roll back ONLY cutover #1: landing-example must revert, while landing-2's
	// concurrent EIH peer AND grant-l2's disabled state MUST remain untouched!
	if _, err := s.RollbackSocketCutover(context.Background(), cut1.ID); err != nil {
		t.Fatalf("RollbackSocketCutover(landing-example): %v", err)
	}
	var gotL1Key, gotL2Key string
	for _, p := range s.nodes[entryCert].Desired.Entry.Peers {
		if p.EgressID == "landing-example" {
			gotL1Key = p.Transport.Key
		}
		if p.EgressID == "landing-2" {
			gotL2Key = p.Transport.Key
		}
	}
	if strings.Contains(gotL1Key, ":") {
		t.Fatalf("cutover #1 rollback did not restore landing-example single-user key: %q", gotL1Key)
	}
	if gotL2Key != l2EIHKey {
		t.Fatalf("cutover #1 rollback clobbered concurrent cutover #2 EIH key: got=%q want=%q", gotL2Key, l2EIHKey)
	}
	foundG2Disabled := false
	for _, g := range s.nodes[entryCert].Desired.Entry.Grants {
		if g.ID == "grant-l2" && !g.Enabled {
			foundG2Disabled = true
		}
	}
	if !foundG2Disabled {
		t.Fatal("cutover #1 rollback clobbered concurrent grant-l2 disabled state")
	}

	// Cutover #2 must still complete cleanly after receipts!
	reportFreshLanding(t, s, target1Cert, target1ID)
	reportFreshLanding(t, s, target2Cert, target2ID)
	reportFreshEntry(t, s, entryCert)
	if done, err := s.AdvanceSocketCutover(context.Background(), cut2.ID); err != nil || !done.Completed {
		t.Fatalf("cutover #2 did not complete cleanly after cutover #1 rollback: %+v err=%v", done, err)
	}
}

func TestSocketCutoverLegacyThreeHopAndDualStackTransportPreservation(t *testing.T) {
	// P1 #4 & P1 #5:
	// 1) Dual-stack landing with IPv4 9.9.9.9:24000 (two-hop-source) AND an active
	//    IPv6 24001 ClientListener must preserve Transport.PublicAddress (Port=0)
	//    during IPv4 24000 cutover so Plan.Validate passes without wedging starting.
	// 2) Legacy three-hop occupying relay:24000 (even alongside a two-hop consumer)
	//    must be inventoried as legacy-three-hop-relay and defer cutover.
	// 3) Legacy three-hop occupying ONLY landing:24000 must be inventoried as
	//    legacy-three-hop-landing and migrate cleanly to EIH 24000.
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }
	targetID := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	relayCert := strings.Repeat("c", 64)
	relayID := enrollPoolTestLanding(t, s, "relay-24000", relayCert, "100.64.0.21", "9.9.9.10", "2001:4860:4860::1111")

	// Enroll a second valid entry (entry-v6) with an active two-hop IPv6 24001
	// ServerTransport and Grant targeting landing-example so normal reconciliation
	// keeps the IPv6 24001 ClientListener alive alongside IPv4 9.9.9.9:24000!
	entryV6Cert := strings.Repeat("9", 64)
	keyV6 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{13}, 16))
	matV6 := s.business.material
	epV6 := matV6.Endpoints[0]
	epV6.ServiceID = "service-v6"
	epV6.Reality.ID = "endpoint-v6"
	epV6.Reality.EntryID = "entry-v6"
	epV6.Reality.InboundTag = "entry-v6-in"
	epV6.Reality.ListenAddress = "100.64.0.9"
	epV6.Reality.IPv4ListenAddress = ""
	epV6.Reality.AdvertiseHost = "entry-v6.example.test"
	matV6.Endpoints = append(slices.Clone(matV6.Endpoints), epV6)
	matV6.References.Applications = maps.Clone(matV6.References.Applications)
	matV6.References.Applications["entry-v6"] = matV6.References.Applications[grant.EntryID]
	matV6.References.Services = maps.Clone(matV6.References.Services)
	svcV6 := matV6.References.Services[matV6.Endpoints[0].ServiceID]
	svcV6.ApplicationID = "entry-v6"
	matV6.References.Services["service-v6"] = svcV6
	nativeV6UUID := "00000000-0000-4000-8000-000000000242"
	routeV6UUID := "00000000-0000-4000-8000-000000000243"
	nativeV6 := glivela.Credential{ID: "cred-native-v6", AccountID: grant.AccountID, Kind: glivela.NativeCredential, User: "native-v6", Identity: glivela.Identity(nativeV6UUID), EntryID: "entry-v6", Enabled: true}
	routeV6 := glivela.Credential{ID: "cred-route-v6", AccountID: grant.AccountID, Kind: glivela.RouteCredential, User: glivela.RouteUser("grant-v6-24001"), Identity: glivela.Identity(routeV6UUID), EntryID: "entry-v6", EgressID: grant.EgressID, Enabled: true}
	grantV6 := glivela.RouteGrant{ID: "grant-v6-24001", AccountID: grant.AccountID, EntryID: "entry-v6", EgressID: grant.EgressID, InboundTag: epV6.Reality.InboundTag, Base: nativeV6, Route: routeV6, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1}
	v6Peer := glivela.RoutePeer{
		EgressID:  grant.EgressID,
		Address:   s.nodes[targetCert].Desired.Landing.Address,
		Port:      24001,
		Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: keyV6, PublicAddress: "2606:4700:4700::1111", Port: 24001, ClientListenerID: "twohop-v6-24001"},
	}
	v6Plan := glivela.XrayPlan{
		Revision:         1,
		RealityEndpoints: []glivela.RealityEndpoint{pinnedImportedReality(epV6)},
		Credentials: []glivela.CredentialMaterial{
			{Credential: nativeV6, ProtocolID: nativeV6UUID},
			{Credential: routeV6, ProtocolID: routeV6UUID},
		},
		Grants: []glivela.RouteGrant{grantV6},
		Peers:  []glivela.RoutePeer{v6Peer},
	}
	v6Net := EntryNetwork{
		Source: &landing.PeerIdentity{ID: "entry-v6-mesh", PublicKey: "nodekey:entry-v6", Address: "100.64.0.9"},
		Peers:  []EntryPeer{{EgressID: grant.EgressID, Identity: targetID, Target: s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Target, ExpectedExit: "8.8.8.8"}},
	}
	v6Desired, err := NewEntryDesired(v6Plan, v6Net)
	if err != nil {
		t.Fatal(err)
	}
	entryV6 := Node{ID: "entry-v6", CertificateID: entryV6Cert, Desired: v6Desired}
	resV6 := glivela.ServerTransport{
		ID: "twohop-v6-24001", Name: "TwoHop V6 24001", AccountID: grant.AccountID, EntryID: "entry-v6", EgressID: grant.EgressID,
		EntryCertificateID: entryV6Cert, LandingCertificateID: targetCert,
		Peer:         v6Peer,
		ExpectedExit: "8.8.8.8",
		Listener:     glivela.TransportListener{ID: "twohop-v6-24001", Port: 24001, Key: keyV6, Source: "2001:4860:4860::8888", Transport: "ipv6-ss2022", Address: "2606:4700:4700::1111", EgressIP: "8.8.8.8"},
	}
	acctsV6 := slices.Clone(matV6.Plan.Accounts)
	acctsV6[0].Credentials = append(slices.Clone(acctsV6[0].Credentials), nativeV6, routeV6)
	acctsV6[0].Grants = append(slices.Clone(acctsV6[0].Grants), grantV6)
	acctsV6[0].Usage = append(slices.Clone(acctsV6[0].Usage),
		glivela.UsageMember{CredentialID: nativeV6.ID, Active: true},
		glivela.UsageMember{CredentialID: routeV6.ID, Active: true},
	)
	matV6.Plan, err = glivela.PlanImport(acctsV6)
	if err != nil {
		t.Fatal(err)
	}
	matV6.ProtocolSecrets = maps.Clone(matV6.ProtocolSecrets)
	matV6.ProtocolSecrets[nativeV6.ID] = nativeV6UUID
	matV6.ProtocolSecrets[routeV6.ID] = routeV6UUID
	matV6.TrafficCounters = maps.Clone(matV6.TrafficCounters)
	matV6.TrafficCounters[nativeV6.ID] = glivela.ImportTrafficCounters{}
	matV6.TrafficCounters[routeV6.ID] = glivela.ImportTrafficCounters{}
	matV6.ServerTransportVersion = glivela.CurrentServerTransportVersion
	matV6.ServerTransports = maps.Clone(matV6.ServerTransports)
	if matV6.ServerTransports == nil {
		matV6.ServerTransports = map[string]glivela.ServerTransport{}
	}
	matV6.ServerTransports[resV6.ID] = resV6
	nodes := s.copy()
	nodes[entryV6Cert] = entryV6
	if err := s.saveOwnedBusinessLocked(matV6); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(nodes); err != nil {
		t.Fatal(err)
	}

	// Activate entry-example's IPv4 two-hop-source grant: normal reconciliation
	// projects entry-v6's IPv6 24001 ClientListener onto landing-example too!
	grant.ID = "grant-v4-src"
	grant.ExpectedRevision = revision()
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.nodes[targetCert].Desired.Landing.ClientListeners, resV6.Listener) {
		t.Fatal("normal reconciliation did not project co-located IPv6 24001 ClientListener onto landing-example")
	}
	reportFreshLanding(t, s, targetCert, targetID)
	reportFreshEntry(t, s, entryCert)
	reportFreshEntry(t, s, entryV6Cert)

	// P1 #5: Cutting over IPv4 9.9.9.9:24000 removes the last Source while keeping
	// IPv6 24001 ClientListener -> Transport.PublicAddress MUST remain (Port==0) and Validate MUST pass!
	startedV4, err := s.StartSocketCutover(context.Background(), "landing-example", "9.9.9.9", s.nodes[targetCert].Desired.Revision)
	if err != nil || startedV4.Phase != "listener-pending" {
		t.Fatalf("P1 #5 dual-stack IPv4 24000 cutover with co-located IPv6 24001 listener failed: %+v err=%v", startedV4, err)
	}
	if s.nodes[targetCert].Desired.Landing.Transport.PublicAddress != "9.9.9.9" || s.nodes[targetCert].Desired.Landing.Transport.Port != 0 {
		t.Fatalf("unexpected Transport after dual-stack IPv4 24000 cutover: %+v", s.nodes[targetCert].Desired.Landing.Transport)
	}
	if !slices.Contains(s.nodes[targetCert].Desired.Landing.ClientListeners, resV6.Listener) {
		t.Fatal("IPv4 24000 cutover dropped co-located IPv6 24001 ClientListener")
	}
	reportFreshLanding(t, s, targetCert, targetID)
	if _, err := s.AdvanceSocketCutover(context.Background(), startedV4.ID); err != nil {
		t.Fatal(err)
	}
	reportFreshEntry(t, s, entryCert)
	if done, err := s.AdvanceSocketCutover(context.Background(), startedV4.ID); err != nil || !done.Completed {
		t.Fatalf("dual-stack IPv4 24000 cutover completion failed: %+v err=%v", done, err)
	}

	var entry Node
	var plan glivela.XrayPlan
	var network EntryNetwork

	// P1 #2, #3, #4: Enroll a PendingLegacyCutover three-hop WITH UDP=true whose
	// relay-24000 is on 24000, whose landing-legacy-24000 is ONLY occupied by this
	// legacy three-hop on 24000, plus a clean second relay (relay-clean) in the pool.
	landing2Cert := strings.Repeat("e", 64)
	landing2ID := enrollPoolTestLanding(t, s, "landing-legacy-24000", landing2Cert, "100.64.0.23", "9.9.9.12", "8.8.8.8")
	relayCleanCert := strings.Repeat("f", 64)
	relayCleanID := enrollPoolTestLanding(t, s, "relay-clean", relayCleanCert, "100.64.0.24", "9.9.9.13", "2001:4860:4860::4444")
	relayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{14}, 16))
	landKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{15}, 16))
	chainID := "legacy-24000"
	relaySpec := &glivela.ClientChainRelay{
		NodeID:        "relay-24000",
		CertificateID: relayCert,
		Port:          24000,
		Key:           relayKey,
		SourceIPv6:    "2001:4860:4860::8888",
		ServerIPv6:    "2001:4860:4860::1111",
	}
	entry = s.nodes[entryCert]
	plan = *entry.Desired.clone().Entry
	network = entry.Desired.EntryNetwork.clone()
	legacyPeer := glivela.RoutePeer{
		EgressID:      "landing-legacy-24000",
		ClientChainID: chainID,
		Address:       "100.64.0.23",
		Port:          24000,
		Relay:         relaySpec,
		Transport:     glivela.PrivateTransport{Protocol: "ss2022", Key: landKey, PublicAddress: "2606:4700:4700::3333", Port: 24000, ClientListenerID: chainID},
	}
	plan.Peers = append(plan.Peers, legacyPeer)
	network.Peers = append(network.Peers, EntryPeer{EgressID: "landing-legacy-24000", ClientChainID: chainID, Identity: landing2ID, RelayIdentity: &relayID, Target: network.Peers[0].Target, ExpectedExit: "8.8.8.8"})
	baseIdx := slices.IndexFunc(plan.Credentials, func(c glivela.CredentialMaterial) bool {
		return c.Credential.Kind == glivela.NativeCredential && c.Credential.AccountID == grant.AccountID && c.Credential.EntryID == grant.EntryID
	})
	if baseIdx < 0 {
		t.Fatal("missing native base credential")
	}
	baseCred := plan.Credentials[baseIdx]
	routeUUID := "00000000-0000-4000-8000-000000000241"
	routeCred := glivela.Credential{ID: "cred-leg-24000", AccountID: grant.AccountID, Kind: glivela.RouteCredential, User: glivela.RouteUser("grant-leg-24000"), Identity: glivela.Identity(routeUUID), EntryID: grant.EntryID, EgressID: "landing-legacy-24000", Enabled: true}
	legGrant := glivela.RouteGrant{ID: "grant-leg-24000", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: "landing-legacy-24000", ClientChainID: chainID, UDP: true, InboundTag: plan.RealityEndpoints[0].InboundTag, Base: baseCred.Credential, Route: routeCred, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1}
	plan.Credentials = append(plan.Credentials, glivela.CredentialMaterial{Credential: routeCred, ProtocolID: routeUUID})
	plan.Grants = append(plan.Grants, legGrant)
	plan.Revision++
	entry.Desired, err = NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal(err)
	}
	relayLis := glivela.TransportListener{ID: chainID, Port: 24000, Key: relayKey, Source: relaySpec.SourceIPv6, Transport: "ipv6-ss2022", Address: relaySpec.ServerIPv6}
	landLis := glivela.TransportListener{ID: chainID, Port: 24000, Key: landKey, Source: relaySpec.ServerIPv6, Transport: "ipv6-ss2022", Address: "2606:4700:4700::3333", EgressIP: "8.8.8.8"}
	legRes := glivela.ServerTransport{
		ID: chainID, Name: "Legacy 24000", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: "landing-legacy-24000",
		EntryCertificateID: entryCert, LandingCertificateID: landing2Cert,
		Peer:          legacyPeer,
		ExpectedExit:  "8.8.8.8",
		Listener:      landLis,
		RelayListener: &relayLis,
	}
	nextMat := s.business.material
	nextMat.ServerTransports = maps.Clone(nextMat.ServerTransports)
	nextMat.ServerTransports[chainID] = legRes
	obsCfg := glivela.DefaultObservatoryConfig()
	nextMat.EntryRelayConfigs = maps.Clone(nextMat.EntryRelayConfigs)
	if nextMat.EntryRelayConfigs == nil {
		nextMat.EntryRelayConfigs = map[string]glivela.EntryRelayConfig{}
	}
	nextMat.EntryRelayConfigs[grant.EntryID] = glivela.EntryRelayConfig{SourceIPv6: "2001:4860:4860::8888", Observatory: &obsCfg}
	nextMat.RelayPools = maps.Clone(nextMat.RelayPools)
	if nextMat.RelayPools == nil {
		nextMat.RelayPools = map[string]glivela.RelayPool{}
	}
	nextMat.RelayPools["pool-leg-24000"] = glivela.RelayPool{
		ID: "pool-leg-24000", Name: "Leg Pool", Revision: 1, Strategy: glivela.DefaultRelayPoolStrategy(2),
		Members: []glivela.RelayPoolMember{
			{NodeID: "relay-24000", CertificateID: relayCert, IngressIPv6: "2001:4860:4860::1111", EgressIPv6: "2001:4860:4860::1111"},
			{NodeID: "relay-clean", CertificateID: relayCleanCert, IngressIPv6: "2001:4860:4860::4444", EgressIPv6: "2001:4860:4860::4444"},
		},
	}
	nextMat.PooledRoutes = maps.Clone(nextMat.PooledRoutes)
	if nextMat.PooledRoutes == nil {
		nextMat.PooledRoutes = map[string]glivela.PooledRoute{}
	}
	nextMat.PooledRoutes[legGrant.ID] = glivela.PooledRoute{
		GrantID: legGrant.ID, AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: "landing-legacy-24000",
		RelayPoolID: "pool-leg-24000", LandingCertificateID: landing2Cert, LandingAddress: "2606:4700:4700::3333",
		ExpectedExit: "8.8.8.8", EgressIP: "8.8.8.8", IngressFamily: "ipv6", LegacyTransportID: chainID, PendingLegacyCutover: true,
	}
	accounts := slices.Clone(nextMat.Plan.Accounts)
	accounts[0].Credentials = append(slices.Clone(accounts[0].Credentials), routeCred)
	accounts[0].Grants = append(slices.Clone(accounts[0].Grants), legGrant)
	accounts[0].Usage = append(slices.Clone(accounts[0].Usage), glivela.UsageMember{CredentialID: routeCred.ID, Active: true})
	nextMat.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		t.Fatal(err)
	}
	nextMat.ProtocolSecrets = maps.Clone(nextMat.ProtocolSecrets)
	nextMat.ProtocolSecrets[routeCred.ID] = routeUUID
	nextMat.TrafficCounters = maps.Clone(nextMat.TrafficCounters)
	nextMat.TrafficCounters[routeCred.ID] = glivela.ImportTrafficCounters{}
	rNode := s.nodes[relayCert]
	rp := *rNode.Desired.clone().Landing
	rp.ClientListeners = []landing.ClientListener{relayLis}
	rp.Revision++
	rNode.Desired, err = NewDesired(rp)
	if err != nil {
		t.Fatal(err)
	}
	l2Node := s.nodes[landing2Cert]
	l2p := *l2Node.Desired.clone().Landing
	l2p.ClientListeners = []landing.ClientListener{landLis}
	l2p.UDPOverTCPListeners = []string{chainID}
	l2p.Revision++
	l2Node.Desired, err = NewDesired(l2p)
	if err != nil {
		t.Fatal(err)
	}
	nodes = s.copy()
	nodes[entryCert], nodes[relayCert], nodes[landing2Cert] = entry, rNode, l2Node
	if err := ensurePooledRouteCredentials(nodes, &nextMat); err != nil {
		t.Fatal(err)
	}
	if err := s.saveOwnedBusinessLocked(nextMat); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(nodes); err != nil {
		t.Fatal(err)
	}
	reportFreshLanding(t, s, relayCert, relayID)
	reportFreshLanding(t, s, relayCleanCert, relayCleanID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	reportFreshEntry(t, s, entryCert)

	// Relay side occupied by legacy three-hop on 24000 MUST be inventoried & deferred!
	relayPlan, err := s.InspectSocketCutover("relay-24000", "2001:4860:4860::1111")
	if err != nil || !relayPlan.Occupied || !relayPlan.Deferred || !slices.ContainsFunc(relayPlan.Consumers, func(c SocketCutoverConsumer) bool { return c.Kind == "legacy-three-hop-relay" }) {
		t.Fatalf("expected legacy-three-hop-relay on 24000 to be inventoried & deferred: %+v err=%v", relayPlan, err)
	}
	if _, err := s.StartSocketCutover(context.Background(), "relay-24000", "2001:4860:4860::1111", s.nodes[relayCert].Desired.Revision); err == nil {
		t.Fatal("StartSocketCutover proceeded on socket occupied by legacy-three-hop-relay")
	}

	// Landing side occupied ONLY by UDP legacy three-hop on 24000 MUST be inventoried as
	// legacy-three-hop-landing, allow real Exchange during listener-pending (P1 #3!),
	// and migrate cleanly to EIH 24000 while keeping relay listener intact!
	landPlan, err := s.InspectSocketCutover("landing-legacy-24000", "2606:4700:4700::3333")
	if err != nil || !landPlan.Occupied || landPlan.Deferred || !slices.ContainsFunc(landPlan.Consumers, func(c SocketCutoverConsumer) bool { return c.Kind == "legacy-three-hop-landing" }) {
		t.Fatalf("expected legacy-three-hop-landing on 24000 ready to migrate: %+v err=%v", landPlan, err)
	}
	startedLeg, err := s.StartSocketCutover(context.Background(), "landing-legacy-24000", "2606:4700:4700::3333", s.nodes[landing2Cert].Desired.Revision)
	if err != nil || startedLeg.Phase != "listener-pending" {
		t.Fatalf("StartSocketCutover(legacy-three-hop-landing) failed: %+v err=%v", startedLeg, err)
	}
	// P1 #3: Real Exchange during listener-pending on UDP legacy three-hop landing MUST NOT deadlock!
	if _, err := s.Exchange(context.Background(), landing2Cert, nil); err != nil {
		t.Fatalf("landing Exchange deadlocked during UDP legacy-three-hop-landing listener-pending: %v", err)
	}
	if _, err := s.Exchange(context.Background(), entryCert, nil); err != nil {
		t.Fatalf("entry Exchange deadlocked during UDP legacy-three-hop-landing listener-pending: %v", err)
	}
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	if _, err := s.AdvanceSocketCutover(context.Background(), startedLeg.ID); err != nil {
		t.Fatalf("AdvanceSocketCutover(legacy-three-hop-landing Stage 2) failed: %v", err)
	}
	// Relay's legacy 24000 listener MUST still be preserved (appendServerListeners didn't drop it!).
	if !slices.Contains(s.nodes[relayCert].Desired.Landing.ClientListeners, relayLis) {
		t.Fatal("migrating legacy-three-hop-landing accidentally withdrew relay's RelayListener")
	}
	reportFreshLanding(t, s, relayCleanCert, relayCleanID)
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	reportFreshEntry(t, s, entryCert)
	// Interleaving guard: CutoverLegacyPooledRoute MUST refuse while startedLeg
	// is still active in entries-pending, preventing a wedged socket cutover!
	if _, err := s.CutoverLegacyPooledRoute(context.Background(), legGrant.ID); err == nil {
		t.Fatal("CutoverLegacyPooledRoute succeeded while related socket cutover was still active")
	}
	if done, err := s.AdvanceSocketCutover(context.Background(), startedLeg.ID); err != nil || !done.Completed {
		t.Fatalf("AdvanceSocketCutover(legacy-three-hop-landing completion) failed: %+v err=%v", done, err)
	}

	// P1 #2: Now cut over legGrant from legacy three-hop (whose landing is ALREADY EIH!)
	// to RelayPool via relay-clean: landing-legacy-24000 MUST retain its old EIH user
	// AND fresh receipt so entry switches straight to relay-clean without dropping legacy EIH!
	oldLandingUsersBefore := len(s.nodes[landing2Cert].Desired.Landing.EIHListeners[0].Users)
	if _, err := s.CutoverLegacyPooledRoute(context.Background(), legGrant.ID); err != nil {
		t.Fatalf("CutoverLegacyPooledRoute after legacy-three-hop-landing EIH cutover failed: %v", err)
	}
	if len(s.nodes[landing2Cert].Desired.Landing.EIHListeners[0].Users) != oldLandingUsersBefore {
		t.Fatalf("P1 #2: CutoverLegacyPooledRoute prematurely withdrew legacy EIH user before entry receipt: before=%d after=%d",
			oldLandingUsersBefore, len(s.nodes[landing2Cert].Desired.Landing.EIHListeners[0].Users))
	}
	if len(s.nodes[entryCert].Desired.Entry.RelayPools) != 1 || len(s.nodes[entryCert].Desired.Entry.RelayPools[0].Candidates) != 1 {
		t.Fatalf("P1 #2: entry did not switch straight to live relay-clean candidate: %+v", s.nodes[entryCert].Desired.Entry.RelayPools)
	}
	// Once entry confirms receipt, legacy ServerTransport & old EIH user retire cleanly!
	reportFreshEntry(t, s, entryCert)
	if _, stillLegacy := s.business.material.ServerTransports[chainID]; stillLegacy {
		t.Fatal("legacy ServerTransport remained after cut-over entry receipt")
	}
	if len(s.nodes[landing2Cert].Desired.Landing.EIHListeners[0].Users) >= oldLandingUsersBefore {
		t.Fatal("obsolete legacy-three-hop-landing EIH user was not withdrawn after entry receipt")
	}
	reportFreshLanding(t, s, landing2Cert, landing2ID)
	if slices.ContainsFunc(slices.Collect(maps.Values(s.business.material.TwoHopEIHBindings)), func(b glivela.TwoHopEIHBinding) bool {
		return b.ServerTransport == chainID
	}) {
		t.Fatal("retired legacy-three-hop-landing TwoHopEIHBinding was not pruned after landing receipt")
	}
}
