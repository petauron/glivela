package control

import (
	"context"
	"maps"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestManagedRouteUDPLifecycle(t *testing.T) {
	s, entryCert, landingCert, change := managedServerLandingFixture(t)
	if _, err := s.ChangeRoute(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	secrets := maps.Clone(s.business.material.ProtocolSecrets)
	counters := maps.Clone(s.business.material.TrafficCounters)
	tokens := maps.Clone(s.business.material.SubscriptionTokens)
	change.ExpectedRevision++
	change.UDP = true
	if _, err := s.ChangeRoute(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	entry, target := s.nodes[entryCert], s.nodes[landingCert]
	if !target.Desired.Landing.Sources[0].TCPOnly || !target.Desired.Landing.Sources[0].UDPOverTCP {
		t.Fatal("TCP source was widened or UDP authorization missing")
	}
	if !strings.Contains(string(target.Desired.Config), `"network":"tcp"`) || !strings.Contains(string(entry.Desired.Config), `"xudpConcurrency":1`) {
		t.Fatal("transport not projected")
	}
	_, grants, err := effectiveBusinessCredentials(s.business.material, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant := grants[change.ID]
	if s.routeUDPApplied(entry, grant) {
		t.Fatal("unapplied capability advertised")
	}
	for _, cert := range []string{entryCert, landingCert} {
		n := s.nodes[cert]
		n.Receipt = &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256, RuntimeReady: true}}
		if cert == landingCert {
			identity := entry.Desired.EntryNetwork.Peers[0].Identity
			n.Receipt.ManagementIdentity = &identity
		}
		n.ReportedAt = time.Now()
		s.nodes[cert] = n
	}
	if !s.routeUDPApplied(s.nodes[entryCert], grant) {
		t.Fatal("applied capability missing")
	}
	stale := s.nodes[landingCert]
	stale.ReportedAt = time.Now().Add(-24 * time.Hour)
	s.nodes[landingCert] = stale
	if !s.routeUDPApplied(s.nodes[entryCert], grant) {
		t.Fatal("health freshness changed configured capability")
	}
	stale.ReportedAt = time.Now()
	s.nodes[landingCert] = stale
	reloaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = reloaded.LoadBusiness(filepath.Join(filepath.Dir(s.path), "business.key")); err != nil {
		t.Fatal(err)
	}
	if !reloaded.nodes[landingCert].Desired.Landing.Sources[0].UDPOverTCP {
		t.Fatal("UDP authorization lost after reload")
	}
	change.ExpectedRevision++
	change.UDP = false
	if _, err = s.ChangeRoute(context.Background(), change); err != nil {
		t.Fatal("disable UDP", err)
	}
	if s.nodes[landingCert].Desired.Landing.Sources[0].UDPOverTCP || strings.Contains(string(s.nodes[entryCert].Desired.Config), `"xudpConcurrency"`) {
		t.Fatal("UDP revocation retained capability")
	}
	if !maps.Equal(secrets, s.business.material.ProtocolSecrets) || !maps.Equal(counters, s.business.material.TrafficCounters) || !maps.Equal(tokens, s.business.material.SubscriptionTokens) {
		t.Fatal("UDP policy changed issued identity or accounting")
	}
}
