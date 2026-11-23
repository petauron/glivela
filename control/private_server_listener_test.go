package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestPrivateServerTransportEnforcesExactBindingWithoutClientLinks(t *testing.T) {
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
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	listenerID, port, exit := "private-server", 24001, "8.8.8.8"
	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	plan.Revision++
	plan.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: link.Address, Port: port, ClientListenerID: listenerID, PrivateLink: link}
	plan.Peers[0].Port = port
	var err error
	entry.Desired, err = NewEntryDesired(plan, *entry.Desired.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	resource := glivela.ServerTransport{
		ID:                   listenerID,
		Name:                 "Private server",
		AccountID:            grant.AccountID,
		EntryID:              grant.EntryID,
		EgressID:             grant.EgressID,
		EntryCertificateID:   entryCert,
		LandingCertificateID: targetCert,
		Peer:                 plan.Peers[0],
		ExpectedExit:         entry.Desired.EntryNetwork.Peers[0].ExpectedExit,
		Listener:             glivela.TransportListener{ID: listenerID, Port: port, Key: key, Source: link.Source, Transport: glivela.IPv4ClientSS2022, Address: link.Address, Interface: link.Interface, EgressIP: exit},
	}
	enrollFixtureServerTransport(t, s, entry, resource)
	target := s.nodes[targetCert]
	identity := entry.Desired.EntryNetwork.Peers[0].Identity
	if _, err = s.Exchange(context.Background(), targetCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	grant.ExpectedRevision = revision()
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	entry = s.nodes[entryCert]
	target = s.nodes[targetCert]
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
			p.Transport.ClientListenerID = "another-listener"
		case "missing-link":
			p.Transport.PrivateLink = nil
		}
		if _, ok := s.boundServerTransport(entry, target, p); ok {
			t.Fatal("accepted mismatched", fault)
		}
	}
	listeners := s.nodes[targetCert].Desired.Landing.ClientListeners
	if len(listeners) != 1 || listeners[0] != resource.Listener {
		t.Fatal("server listener was not projected")
	}
	if _, changed, err := projectBusinessEntries(s.nodes, s.business.material, time.Now()); err != nil || changed {
		t.Fatalf("idempotent projection altered private server listener: changed=%v err=%v", changed, err)
	}
	if !serverOwnsListener(s.business.material, listenerID) {
		t.Fatal("server binding lost")
	}
	if len(s.nodes[entryCert].Desired.Entry.ClientLinks) != 0 {
		t.Fatal("server route granted direct client LAN access")
	}
	if !reflect.DeepEqual(before.SubscriptionTokens, s.business.material.SubscriptionTokens) {
		t.Fatal("subscription identity changed")
	}
	raw := string(s.nodes[entryCert].Desired.Config)
	if !strings.Contains(raw, link.Address) || !strings.Contains(raw, `"sendThrough":"`+link.Source+`"`) {
		t.Fatal("server outbound did not bind private path")
	}
}
