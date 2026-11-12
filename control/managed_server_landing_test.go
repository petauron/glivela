package control

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func managedServerLandingFixture(t *testing.T) (*Store, string, string, RouteChange) {
	t.Helper()
	source, direct, _, _ := subscriptionFixture(t, false)
	routed := withRoutedEntry(t, direct)
	plan := *direct.Entry
	plan.Peers = routed.Entry.Peers
	transport := glivela.PrivateTransport{Protocol: "ss2022", PublicAddress: "9.9.9.9", Port: 24000, Key: "MDEyMzQ1Njc4OWFiY2RlZg=="}
	plan.Peers[0].Transport, plan.Peers[0].Port = transport, 24000
	desired, err := NewEntryDesired(plan, *routed.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	material := source.business.material
	material.Ownership = nil
	s, _, entryCert, landingCert := ownedSubscriptionFixture(t, material, desired, true)
	target := s.nodes[landingCert]
	p := *target.Desired.Landing
	p.Revision++
	p.Transport = transport
	p.Sources[0].TCPOnly, p.Sources[0].PublicAddress = true, "8.8.4.4"
	target.Desired, err = NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(target); err != nil {
		t.Fatal(err)
	}
	target = s.nodes[landingCert]
	identity := s.nodes[entryCert].Desired.EntryNetwork.Peers[0].Identity
	if _, err = s.Exchange(context.Background(), landingCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
		t.Fatal(err)
	}
	change := RouteChange{ID: "managed-server-route", AccountID: "account-example", EntryID: "entry-example", EgressID: "landing-example", Enabled: true}
	for _, account := range s.business.material.Plan.Accounts {
		if account.Account.ID == change.AccountID {
			change.ExpectedRevision = account.Account.DesiredRevision
		}
	}
	return s, entryCert, landingCert, change
}

func TestManagedServerLandingGrant(t *testing.T) {
	s, _, landingCert, change := managedServerLandingFixture(t)
	before := s.business.material
	if _, imported := before.References.Nodes[change.EgressID]; imported || len(before.ClientChains) != 0 || len(before.ClientLandings) != 0 {
		t.Fatal("fixture must have no imported or client-chain authority")
	}
	if _, err := s.ChangeRoute(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	m := s.business.material
	if m.ManagedRouteLandings[change.ID] != landingCert || len(m.ClientChains) != 0 || len(m.ClientLandings) != 0 {
		t.Fatal("grant must bind actual certificate without client enrollment")
	}
	for id, secret := range before.ProtocolSecrets {
		if m.ProtocolSecrets[id] != secret || m.TrafficCounters[id] != before.TrafficCounters[id] {
			t.Fatal("existing identity or accounting changed")
		}
	}
	for id, token := range before.SubscriptionTokens {
		if m.SubscriptionTokens[id] != token {
			t.Fatal("subscription token changed")
		}
	}
	reloaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = reloaded.LoadBusiness(filepath.Join(filepath.Dir(s.path), "business.key")); err != nil {
		t.Fatal("grant failed reload:", err)
	}
	for _, fault := range []string{"orphan", "bad-certificate"} {
		bad := reloaded.business.material
		bad.ManagedRouteLandings = map[string]string{change.ID: landingCert}
		if fault == "orphan" {
			bad.ManagedRouteLandings["missing-grant"] = landingCert
		} else {
			bad.ManagedRouteLandings[change.ID] = strings.Repeat("z", 64)
		}
		if bad.Validate() == nil {
			t.Fatal("invalid managed authority accepted", fault)
		}
	}
	// Disabling remains possible when the landing is offline. Re-enabling requires
	// current mutual enrollment and the originally captured certificate.
	n := s.nodes[landingCert]
	n.ReportedAt = time.Now().Add(-24 * time.Hour)
	s.nodes[landingCert] = n
	change.ExpectedRevision++
	change.Enabled = false
	if _, err = s.ChangeRoute(context.Background(), change); err != nil {
		t.Fatal("offline revoke refused:", err)
	}
	change.ExpectedRevision++
	change.Enabled = true
	saved := businessBytes(t, s)
	if _, err = s.ChangeRoute(context.Background(), change); err == nil || !bytes.Equal(saved, businessBytes(t, s)) {
		t.Fatal("stale re-enable changed business")
	}
}

func TestManagedServerLandingRejectsUnprovenGrant(t *testing.T) {
	for _, fault := range []string{"stale", "source-certificate", "source-address", "target-identity", "foreign-owner"} {
		t.Run(fault, func(t *testing.T) {
			s, _, landingCert, change := managedServerLandingFixture(t)
			n := s.nodes[landingCert]
			switch fault {
			case "stale":
				n.ReportedAt = time.Now().Add(-24 * time.Hour)
			case "source-certificate":
				r := n.RouteEntries[change.EntryID]
				r.CertificateID = landingCert
				n.RouteEntries[change.EntryID] = r
			case "source-address":
				r := n.RouteEntries[change.EntryID]
				r.Address = "100.64.0.99"
				n.RouteEntries[change.EntryID] = r
			case "target-identity":
				identity := *n.Receipt.ManagementIdentity
				identity.PublicKey = "nodekey:other"
				n.Receipt.ManagementIdentity = &identity
			case "foreign-owner":
				s.business.material.ClientLandings = map[string]glivela.ClientLanding{change.EgressID: {AccountID: "account-other", Key: "MDEyMzQ1Njc4OWFiY2RlZg=="}}
			}
			s.nodes[landingCert] = n
			before := businessBytes(t, s)
			if _, err := s.ChangeRoute(context.Background(), change); err == nil || !bytes.Equal(before, businessBytes(t, s)) {
				t.Fatal("unproven enrollment changed business")
			}
		})
	}
}
