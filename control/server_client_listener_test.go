package control

import (
	"context"
	glivela "github.com/petauron/glivela"
	"reflect"
	"strings"
	"testing"
	"time"
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
	exit := "8.8.8.8"
	change := ClientChainChange{EgressIP: &exit, ID: "existing-listener", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID, Name: "Existing IPv6", Enabled: true, Transport: "ipv6-ss2022", SourceIPv6: "2001:4860:4860::8888", ServerIPv6: "2606:4700:4700::1111", ExpectedRevision: revision()}
	if _, err := s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	c, err := s.business.material.EffectiveClientChain(s.business.material.ClientChains[0])
	if err != nil {
		t.Fatal(err)
	}
	entry := s.nodes[entryCert]
	plan := *entry.Desired.Entry
	plan.Revision++
	plan.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: c.Key, PublicAddress: c.ServerIPv6, Port: c.Port, ClientListenerID: c.ID}
	plan.Peers[0].Port = c.Port
	entry.Desired, err = NewEntryDesired(plan, *entry.Desired.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(entry); err != nil {
		t.Fatal(err)
	}
	target := s.nodes[targetCert]
	// A public IPv6 client listener does not need a legacy IPv4 source grant.
	landingPlan := *target.Desired.Landing
	landingPlan.Revision++
	landingPlan.Sources = nil
	target.Desired, err = NewDesired(landingPlan)
	if err != nil {
		t.Fatal(err)
	}
	target.RouteEntries = nil
	if err = s.Put(target); err != nil {
		t.Fatal(err)
	}
	target = s.nodes[targetCert]
	before := *target.Desired.Landing
	identity := entry.Desired.EntryNetwork.Peers[0].Identity
	if _, err = s.Exchange(context.Background(), targetCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	entry = s.nodes[entryCert]
	target = s.nodes[targetCert]
	if _, ok := s.boundClientListener(entry, target, plan.Peers[0]); !ok {
		t.Fatalf("valid existing listener rejected: expected exit %s landing %s override %s", entry.Desired.EntryNetwork.Peers[0].ExpectedExit, target.Desired.Landing.EgressIP, c.EgressIP)
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
		if _, ok := s.boundClientListener(entry, target, peer); ok {
			t.Fatal("accepted mismatched", fault)
		}
	}
	grant.ExpectedRevision = revision()
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("server grant", err)
	}

	checkPublished := func() {
		t.Helper()
		_, grants, err := effectiveBusinessCredentials(s.business.material, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		protocolID := s.business.material.ProtocolSecrets[grants[grant.ID].Route.ID]
		response := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
		if protocolID == "" || response.Code != 200 || !strings.Contains(response.Body.String(), protocolID) {
			t.Fatal("bound server VLESS missing from actual subscription", response.Code)
		}
		targets := s.latencyTargetsLocked()
		target, ok := targets[latencyPathKey(grant.EntryID, grant.EgressID, c.Port, c.SourceIPv6, c.ServerIPv6)]
		if !ok || target.Source != c.SourceIPv6 || target.Address != c.ServerIPv6 || target.Port != c.Port {
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
	}
	checkPublished()
	change.ExpectedRevision = revision()
	change.Enabled = false
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal("withdraw client publication", err)
	}
	checkPublished()
	after := *s.nodes[targetCert].Desired.Landing
	after.Revision = before.Revision
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("listener retention failed: before=%d after=%d used=%v", len(before.ClientListeners), len(s.nodes[targetCert].Desired.Landing.ClientListeners), clientListenerUsedByServer(s.nodes, s.business.material, c, time.Now()))
	}
	if !clientListenerUsedByServer(s.nodes, s.business.material, c, time.Now()) {
		t.Fatal("enabled server grant did not retain listener")
	}
	_, grants, err := effectiveBusinessCredentials(s.business.material, time.Now())
	if err != nil {
		t.Fatal(err)
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

}
