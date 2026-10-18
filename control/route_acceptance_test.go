package control

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLandingAcceptanceRequiresAllRoutesAndFreshRuntime(t *testing.T) {
	s := store(t)
	d := artifact(1)
	cert := strings.Repeat("a", 64)
	entryCert := strings.Repeat("b", 64)
	if err := s.Put(Node{ID: "landing-a", CertificateID: cert, Desired: d}); err != nil {
		t.Fatal(err)
	}
	entries := []string{"entry-a", "entry-b"}
	assert := func(reason string, ready, passed bool) {
		t.Helper()
		got, err := s.AcceptLandingRoutes("landing-a", "snapshot-a", d.Revision, d.ConfigSHA256, entries)
		if err != nil || got.Reason != reason || got.RuntimeReady != ready || got.RoutesPassed != passed {
			t.Fatalf("gate: %+v %v", got, err)
		}
	}
	assert("runtime-unverified", false, false)
	reportRuntime(t, s, cert, d)
	assert("routes-incomplete", true, false)
	for _, entry := range entries {
		p := RouteProbe{SnapshotID: "snapshot-a", EntryID: entry, LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
		if err := s.AssignRouteCheck(entryCert, p); err != nil {
			t.Fatal(err)
		}
		p = s.nodes[cert].Checks[entry].Request
		r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: entry, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
		if _, err := s.RouteExchange(context.Background(), entryCert, &r); err != nil {
			t.Fatal(err)
		}
		if entry == "entry-a" {
			assert("routes-incomplete", true, false)
		}
	}
	assert("verified", true, true)
	check := s.nodes[cert].Checks["entry-a"]
	check.ReceivedAt = time.Now().Add(-6 * time.Minute)
	s.nodes[cert].Checks["entry-a"] = check
	assert("route-expired", true, false)
	if _, err := s.Exchange(context.Background(), cert, nil); err != nil {
		t.Fatal(err)
	}
	assert("runtime-unverified", false, false)
	if _, err := s.AcceptLandingRoutes("landing-a", "snapshot-a", d.Revision, d.ConfigSHA256, nil); err == nil {
		t.Fatal("empty inventory accepted")
	}
}
