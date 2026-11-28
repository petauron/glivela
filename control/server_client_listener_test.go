package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestServerReusesIssuedIPv6Listener(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 {
		for _, a := range s.business.material.Plan.Accounts {
			if a.Account.ID == grant.AccountID {
				return a.Account.DesiredRevision
			}
		}
		t.Fatal("account missing")
		return 0
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	sourceIPv6, serverIPv6, port, listenerID := "2001:4860:4860::8888", "2606:4700:4700::1111", 24001, "existing-listener"
	exit := "8.8.8.8"
	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	plan.Revision++
	plan.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: serverIPv6, Port: port, ClientListenerID: listenerID}
	plan.Peers[0].Port = port
	var err error
	entry.Desired, err = NewEntryDesired(plan, *entry.Desired.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	// A public IPv6 server listener does not need a legacy IPv4 source grant.
	target := s.nodes[targetCert]
	landingPlan := *target.Desired.clone().Landing
	landingPlan.Revision++
	landingPlan.Sources = nil
	target.Desired, err = NewDesired(landingPlan)
	if err != nil {
		t.Fatal(err)
	}
	target.RouteEntries = nil
	target.Checks = nil
	target.Receipt, target.ReportedAt = nil, time.Time{}
	if err = s.Put(target); err != nil {
		t.Fatal(err)
	}
	resource := glivela.ServerTransport{
		ID:                   listenerID,
		Name:                 "Existing IPv6",
		AccountID:            grant.AccountID,
		EntryID:              grant.EntryID,
		EgressID:             grant.EgressID,
		EntryCertificateID:   entryCert,
		LandingCertificateID: targetCert,
		Peer:                 plan.Peers[0],
		ExpectedExit:         entry.Desired.EntryNetwork.Peers[0].ExpectedExit,
		Listener:             glivela.TransportListener{ID: listenerID, Port: port, Key: key, Source: sourceIPv6, Transport: "ipv6-ss2022", Address: serverIPv6, EgressIP: exit},
	}
	enrollFixtureServerTransport(t, s, entry, resource)
	target = s.nodes[targetCert]
	identity := entry.Desired.EntryNetwork.Peers[0].Identity
	if _, err = s.Exchange(context.Background(), targetCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	grant.ExpectedRevision = revision()
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("server grant", err)
	}
	target = s.nodes[targetCert]
	if _, err = s.Exchange(context.Background(), targetCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	entry = s.nodes[entryCert]
	target = s.nodes[targetCert]
	before := *target.Desired.Landing
	if _, ok := s.boundServerTransport(entry, target, plan.Peers[0]); !ok {
		t.Fatalf("valid existing listener rejected: expected exit %s landing %s override %s", entry.Desired.EntryNetwork.Peers[0].ExpectedExit, target.Desired.Landing.EgressIP, exit)
	}
	for _, fault := range []string{"key", "port", "address", "listener"} {
		peer := plan.Peers[0]
		switch fault {
		case "key":
			peer.Transport.Key = "MDEyMzQ1Njc4OWFiY2RlZg=="
		case "port":
			peer.Port++
		case "address":
			peer.Transport.PublicAddress = "2606:4700:4700::1001"
		case "listener":
			peer.Transport.ClientListenerID = "other-listener"
		}
		if _, ok := s.boundServerTransport(entry, target, peer); ok {
			t.Fatal("accepted mismatched", fault)
		}
	}
	_, grants, err := effectiveBusinessCredentials(s.business.material, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	protocolID := s.business.material.ProtocolSecrets[grants[grant.ID].Route.ID]
	response := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
	if protocolID == "" || response.Code != 200 || !strings.Contains(response.Body.String(), protocolID) || strings.Contains(response.Body.String(), "dialer-proxy:") {
		t.Fatal("bound server VLESS missing or unexpected dialer-proxy in subscription", response.Code)
	}
	targets := s.latencyTargetsLocked()
	lt, ok := targets[latencyPathKey(grant.EntryID, grant.EgressID, port, sourceIPv6, serverIPv6)]
	if !ok || lt.Source != sourceIPv6 || lt.Address != serverIPv6 || lt.Port != port {
		t.Fatal("bound listener latency path lost")
	}
	node := s.nodes[entryCert]
	observation := healthyEntryObservation(node.Desired, time.Now())
	for id, peer := range observation.EntryHealth.Peers {
		peer.Status.LinkState = "authenticated"
		observation.EntryHealth.Peers[id] = peer
	}
	if _, err = s.Exchange(context.Background(), entryCert, &observation); err != nil {
		t.Fatal(err)
	}
	if !s.subscriptionPeerReady(s.nodes[entryCert], grant.EgressID, time.Now()) {
		t.Fatal("current bound startup acceptance not reflected")
	}
	if _, changed, err := projectBusinessEntries(s.nodes, s.business.material, time.Now()); err != nil || changed {
		t.Fatalf("idempotent projection altered server listener: changed=%v err=%v", changed, err)
	}
	after := *s.nodes[targetCert].Desired.Landing
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("listener retention failed: before=%d after=%d used=%v", len(before.ClientListeners), len(s.nodes[targetCert].Desired.Landing.ClientListeners), serverOwnsListener(s.business.material, listenerID))
	}
	if !serverOwnsListener(s.business.material, listenerID) {
		t.Fatal("enabled server grant did not retain listener")
	}
	for _, g := range grants {
		if g.ID == grant.ID && (!g.Enabled || !g.Route.Enabled) {
			t.Fatal("server grant disabled")
		}
	}
	if len(s.nodes[targetCert].Desired.Landing.ClientListeners) != 1 {
		t.Fatal("listener lost")
	}
	grant.ExpectedRevision = revision()
	grant.Enabled = false
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("server revoke", err)
	}
	if len(s.nodes[targetCert].Desired.Landing.ClientListeners) != 0 {
		t.Fatal("revoked final publication retained socket")
	}
	// Creating a new server grant on an idle enrolled ServerTransport must succeed
	// once the target landing reports a fresh receipt, and re-project its listener.
	target = s.nodes[targetCert]
	if _, err = s.Exchange(context.Background(), targetCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	freshGrant := grant
	freshGrant.ID = "recreated-server-route"
	freshGrant.Enabled = true
	freshGrant.ExpectedRevision = revision()
	if _, err = s.ChangeRoute(context.Background(), freshGrant); err != nil {
		t.Fatal("new grant on idle ServerTransport refused:", err)
	}
	if len(s.nodes[targetCert].Desired.Landing.ClientListeners) != 1 || s.nodes[targetCert].Desired.Landing.ClientListeners[0] != resource.Listener {
		t.Fatal("new grant on idle ServerTransport did not re-project listener")
	}
}

// Fixture-only enrollment: register an idle server-owned transport record and
// its matching entry peer without projecting landing listeners until a server
// route grant enables it.
func enrollFixtureServerTransport(t *testing.T, s *Store, entry Node, resource glivela.ServerTransport) {
	t.Helper()
	if err := resource.Validate(); err != nil {
		t.Fatal("invalid fixture server transport:", err)
	}
	entry.Receipt, entry.ReportedAt = nil, time.Time{}
	nodes := s.copy()
	nodes[entry.CertificateID] = entry
	next := s.business.material
	next.ServerTransportVersion = glivela.CurrentServerTransportVersion
	next.ServerTransports = maps.Clone(next.ServerTransports)
	if next.ServerTransports == nil {
		next.ServerTransports = map[string]glivela.ServerTransport{}
	}
	next.ServerTransports[resource.ID] = resource
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(nodes); err != nil {
		t.Fatal(err)
	}
}
