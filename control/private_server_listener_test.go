package control

import (
	"context"
	glivela "github.com/petauron/glivela"
	"reflect"
	"strings"
	"testing"
)

func TestPrivateServerReusesListenerAfterClientWithdrawn(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 {
		for _, a := range s.business.material.Plan.Accounts {
			if a.Account.ID == grant.AccountID {
				return a.Account.DesiredRevision
			}
		}
		t.Fatal("missing account")
		return 0
	}
	link := &glivela.PrivateClientLink{Source: "10.20.0.3", Address: "10.20.0.2", SourceInterface: "ens8", Interface: "ens8"}
	exit := "8.8.8.8"
	change := ClientChainChange{EgressIP: &exit, ID: "private-client", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID, Name: "Private client", Enabled: true, Transport: glivela.IPv4ClientSS2022, PrivateLink: link, ExpectedRevision: revision()}
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
	plan.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: c.Key, PublicAddress: link.Address, Port: c.Port, ClientListenerID: c.ID, PrivateLink: link}
	plan.Peers[0].Port = c.Port
	entry.Desired, err = NewEntryDesired(plan, *entry.Desired.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	ownServerFixtureTransports(t, s, entry)
	if err = s.Put(entry); err != nil {
		t.Fatal(err)
	}
	entry = s.nodes[entryCert]
	target := s.nodes[targetCert]
	if _, ok := s.boundServerTransport(entry, target, entry.Desired.Entry.Peers[0]); !ok {
		t.Fatal("enrolled private listener rejected")
	}
	for _, fault := range []string{"source", "destination", "interface", "key", "listener", "missing-link"} {
		p := entry.Desired.clone().Entry.Peers[0]
		switch fault {
		case "source":
			p.Transport.PrivateLink.Source = "10.20.0.4"
		case "destination":
			p.Transport.PublicAddress = "10.20.0.4"
		case "interface":
			p.Transport.PrivateLink.SourceInterface = "ens9"
		case "key":
			p.Transport.Key = "MDEyMzQ1Njc4OWFiY2RlZg=="
		case "listener":
			p.Transport.ClientListenerID = "another-client"
		case "missing-link":
			p.Transport.PrivateLink = nil
		}
		if _, ok := s.boundServerTransport(entry, target, p); ok {
			t.Fatal("accepted mismatched", fault)
		}
	}
	identity := entry.Desired.EntryNetwork.Peers[0].Identity
	if _, err = s.Exchange(context.Background(), targetCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	grant.ExpectedRevision = revision()
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	listeners := s.nodes[targetCert].Desired.Landing.ClientListeners
	change.Enabled = false
	change.ExpectedRevision = revision()
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal("client withdrawal", err)
	}
	if !reflect.DeepEqual(listeners, s.nodes[targetCert].Desired.Landing.ClientListeners) {
		t.Fatal("server listener was removed or changed")
	}
	if !serverOwnsListener(s.business.material, c.ID) {
		t.Fatal("server binding lost")
	}
	if len(s.nodes[entryCert].Desired.Entry.ClientLinks) != 0 {
		t.Fatal("withdrawn client retained direct LAN access")
	}
	if !reflect.DeepEqual(before.SubscriptionTokens, s.business.material.SubscriptionTokens) || !reflect.DeepEqual(before.TrafficCounters, s.business.material.TrafficCounters) || !reflect.DeepEqual(before.ProtocolSecrets, s.business.material.ProtocolSecrets) {
		t.Fatal("subscription identity or accounting changed")
	}
	change.ClearPrivateLink = true
	change.PrivateLink = nil
	change.ExpectedRevision = revision()
	if _, err = s.ChangeClientChain(context.Background(), change); err == nil {
		t.Fatal("live server private binding removed")
	}
	raw := string(s.nodes[entryCert].Desired.Config)
	if !strings.Contains(raw, link.Address) || !strings.Contains(raw, `"sendThrough":"`+link.Source+`"`) {
		t.Fatal("server outbound did not bind private path")
	}
}
