package control

import (
	"context"
	"github.com/petauron/glivela/landing"
	"strings"
	"testing"
	"time"
)

func TestLandingAcceptanceRequiresAllRoutesAndFreshRuntime(t *testing.T) {
	s := store(t)
	plan := artifact(1).Landing
	plan.Sources = append(plan.Sources, landing.Source{Address: "100.64.0.4"})
	d, err := NewDesired(*plan)
	if err != nil {
		t.Fatal(err)
	}
	cert := strings.Repeat("a", 64)
	entryCert := strings.Repeat("b", 64)
	secondCert := strings.Repeat("c", 64)
	entryCertificates := map[string]string{"entry-a": entryCert, "entry-b": secondCert}
	if err := s.Put(Node{ID: "landing-a", CertificateID: cert, Desired: d, RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: entryCert, Address: "100.64.0.3"}, "entry-b": {CertificateID: secondCert, Address: "100.64.0.4"}}}); err != nil {
		t.Fatal(err)
	}
	entries := []string{"entry-a", "entry-b"}
	assert := func(reason string, ready, passed bool) {
		t.Helper()
		got, err := s.AcceptLandingRoutes("landing-a", "snapshot-a", d.Revision, d.ConfigSHA256)
		if err != nil || got.Reason != reason || got.RuntimeReady != ready || got.RoutesPassed != passed {
			t.Fatalf("gate: %+v %v", got, err)
		}
	}
	assert("runtime-unverified", false, false)
	reportRuntime(t, s, cert, d)
	assert("routes-incomplete", true, false)
	var assignments []RouteCheck
	for _, entry := range entries {
		p := RouteProbe{SnapshotID: "snapshot-a", EntryID: entry, LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
		assignments = append(assignments, RouteCheck{CertificateID: entryCertificates[entry], Request: p})
	}
	if err := s.AssignRouteChecks(assignments); err != nil {
		t.Fatal(err)
	}
	firstAttempt := s.nodes[cert].Checks["entry-a"].Request.AttemptID
	if err := s.AssignRouteChecks(assignments[:1]); err == nil {
		t.Fatal("subset replaced the independently enrolled full inventory")
	}
	wrongPeer := append([]RouteCheck(nil), assignments...)
	wrongPeer[1].CertificateID = entryCert
	if err := s.AssignRouteChecks(wrongPeer); err == nil {
		t.Fatal("one entry certificate impersonated another entry")
	}
	bad := append([]RouteCheck(nil), assignments...)
	bad[1].Request.SnapshotID = "different-snapshot"
	if err := s.AssignRouteChecks(bad); err == nil {
		t.Fatal("mixed snapshot accepted")
	}
	if len(s.nodes[cert].Checks) != 2 || s.nodes[cert].Checks["entry-a"].Request.AttemptID != firstAttempt {
		t.Fatal("invalid batch partially replaced operation")
	}
	s, err = OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		p := s.nodes[cert].Checks[entry].Request
		r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: entry, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
		if _, err := s.RouteExchange(context.Background(), entryCertificates[entry], &r); err != nil {
			t.Fatal(err)
		}
		if entry == "entry-a" {
			assert("routes-incomplete", true, false)
		}
	}
	assert("verified", true, true)
	removed := s.nodes[cert].Checks["entry-b"]
	delete(s.nodes[cert].Checks, "entry-b")
	assert("routes-incomplete", true, false)
	if err := s.commit(s.nodes); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(s.path); err == nil {
		t.Fatal("truncated persisted inventory accepted")
	}
	s.nodes[cert].Checks["entry-b"] = removed
	check := s.nodes[cert].Checks["entry-a"]
	check.ReceivedAt = time.Now().Add(-6 * time.Minute)
	s.nodes[cert].Checks["entry-a"] = check
	assert("route-expired", true, false)
	if _, err := s.Exchange(context.Background(), cert, nil); err != nil {
		t.Fatal(err)
	}
	assert("runtime-unverified", false, false)
	if err := s.AssignRouteChecks(nil); err == nil {
		t.Fatal("empty inventory accepted")
	}
}

func TestLandingTemporarySuspensionPreservesSourcesAndRequiresRecovery(t *testing.T) {
	s := store(t)
	plan := artifact(1).Landing
	plan.Sources = append(plan.Sources, landing.Source{Address: "100.64.0.4"})
	d, err := NewDesired(*plan)
	if err != nil {
		t.Fatal(err)
	}
	cert, first, second := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	if err := s.Put(Node{ID: "landing-a", CertificateID: cert, Desired: d, RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: first, Address: "100.64.0.3"}, "entry-b": {CertificateID: second, Address: "100.64.0.4"}}}); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, cert, d)
	if err := s.SetAvailability("unknown", "maintenance", time.Time{}, s.availability.Revision); err == nil {
		t.Fatal("unknown exclusion accepted")
	}
	if err := s.SetAvailability("entry-b", "traffic-exhausted", time.Now().Add(time.Hour), s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	p := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: first, Request: p}}); err != nil {
		t.Fatal(err)
	}
	p = s.nodes[cert].Checks["entry-a"].Request
	r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
	if _, err := s.RouteExchange(context.Background(), first, &r); err != nil {
		t.Fatal(err)
	}
	gate, err := s.AcceptLandingRoutes("landing-a", p.SnapshotID, d.Revision, d.ConfigSHA256)
	if err != nil || !gate.RoutesPassed || gate.Reason != "verified-active-entries" || len(gate.DeferredEntries) != 1 || gate.DeferredEntries[0] != "entry-b" {
		t.Fatalf("unexpected acceptance %+v %v", gate, err)
	}
	if len(s.nodes[cert].Desired.Landing.Sources) != 2 || len(s.nodes[cert].RouteEntries) != 2 {
		t.Fatal("source authorization lost")
	}
	s, err = OpenStore(s.path)
	if err != nil || !s.suspended("entry-b", time.Now()) {
		t.Fatal("suspension did not survive restart", err)
	}
	if err := s.SetAvailability("entry-b", "resume", time.Time{}, s.availability.Revision-1); err == nil {
		t.Fatal("stale mutation accepted")
	}
	if err := s.SetAvailability("entry-b", "resume", time.Time{}, s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	gate, err = s.AcceptLandingRoutes("landing-a", p.SnapshotID, d.Revision, d.ConfigSHA256)
	if err != nil || gate.RoutesPassed || gate.Reason != "routes-incomplete" {
		t.Fatal("resume manufactured success", gate, err)
	}
	if err := s.SetAvailability("entry-a", "maintenance", time.Time{}, s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAvailability("entry-b", "maintenance", time.Time{}, s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	gate, err = s.AcceptLandingRoutes("landing-a", p.SnapshotID, d.Revision, d.ConfigSHA256)
	if err != nil || gate.RoutesPassed {
		t.Fatal("zero active checks accepted", gate, err)
	}
}
