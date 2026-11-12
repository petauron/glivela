package control

import (
	"context"
	glivela "github.com/petauron/glivela"
	"reflect"
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
	change.ExpectedRevision = revision()
	change.Enabled = false
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal("withdraw client publication", err)
	}
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
