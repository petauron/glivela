package control

import (
	"context"
	glivela "github.com/petauron/glivela"
	"strings"
	"testing"
	"time"
)

func reportRuntime(t *testing.T, s *Store, certificate string, d Desired) {
	t.Helper()
	if _, err := s.Exchange(context.Background(), certificate, &glivela.AppliedReceipt{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, RuntimeReady: true}); err != nil {
		t.Fatal(err)
	}
}

func TestRouteAttemptsAreBoundAndDurable(t *testing.T) {
	s := store(t)
	landing, entry := strings.Repeat("a", 64), strings.Repeat("b", 64)
	d := artifact(1)
	if err := s.Put(Node{ID: "landing-a", CertificateID: landing, Desired: d}); err != nil {
		t.Fatal(err)
	}
	p := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entry, Request: p}}); err == nil {
		t.Fatal("desired state treated as applied runtime")
	}
	reportRuntime(t, s, landing, d)
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entry, Request: p}}); err != nil {
		t.Fatal(err)
	}
	pending, err := s.RouteExchange(context.Background(), entry, nil)
	if err != nil || len(pending) != 1 {
		t.Fatalf("assignment: %v %v", pending, err)
	}
	p = pending[0]
	r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now().UTC(), TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit, Passed: true}
	if _, err := s.RouteExchange(context.Background(), landing, &r); err == nil {
		t.Fatal("wrong peer accepted")
	}
	wrong := r
	wrong.AttemptID = "old-attempt"
	if _, err := s.RouteExchange(context.Background(), entry, &wrong); err == nil {
		t.Fatal("wrong attempt accepted")
	}
	if _, err := s.Exchange(context.Background(), landing, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RouteExchange(context.Background(), entry, &r); err == nil {
		t.Fatal("route success accepted after runtime proof lost")
	}
	hidden, err := s.RouteExchange(context.Background(), entry, nil)
	if err != nil || len(hidden) != 0 {
		t.Fatal("unhealthy runtime still dispatched")
	}
	reportRuntime(t, s, landing, d)
	if _, err := s.RouteExchange(context.Background(), entry, &r); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	received := s.nodes[landing].Checks[p.EntryID].ReceivedAt
	if received.IsZero() {
		t.Fatal("receipt not persisted")
	}
	if _, err := s.RouteExchange(context.Background(), entry, &r); err != nil {
		t.Fatal(err)
	}
	if !s.nodes[landing].Checks[p.EntryID].ReceivedAt.Equal(received) {
		t.Fatal("replay refreshed health")
	}
	wrong = r
	wrong.DurationMillis++
	if _, err := s.RouteExchange(context.Background(), entry, &wrong); err == nil {
		t.Fatal("changed replay accepted")
	}
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entry, Request: p}}); err != nil {
		t.Fatal(err)
	}
	if s.nodes[landing].Checks[p.EntryID].Result != nil {
		t.Fatal("retry retained old success")
	}
	if _, err := s.RouteExchange(context.Background(), entry, &r); err == nil {
		t.Fatal("previous attempt accepted after retry")
	}
	if err := s.Put(Node{ID: "landing-a", CertificateID: landing, Desired: artifact(2)}); err != nil {
		t.Fatal(err)
	}
	if len(s.nodes[landing].Checks) != 0 {
		t.Fatal("new revision retained checks")
	}
	if _, err := s.RouteExchange(context.Background(), entry, &r); err == nil {
		t.Fatal("old revision accepted")
	}
}

func TestRouteResultRequiresActualTLSAndExit(t *testing.T) {
	p := RouteProbe{AttemptID: "attempt", SnapshotID: "snapshot", EntryID: "entry", LandingID: "landing", Revision: 1, ConfigSHA256: strings.Repeat("a", 64), ExpectedExit: "2606:4700::1"}
	r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: 1, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: "2606:4700:0:0:0:0:0:1"}
	if err := validateRouteResult(p, r); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RouteProbeResult){func(r *RouteProbeResult) { r.TLSVerified = false }, func(r *RouteProbeResult) { r.HTTPStatus = 404 }, func(r *RouteProbeResult) { r.ObservedExit = "203.0.113.8" }, func(r *RouteProbeResult) { r.CheckedAt = time.Time{} }} {
		bad := r
		change(&bad)
		if validateRouteResult(p, bad) == nil {
			t.Fatal("incomplete proof accepted")
		}
	}
}

func TestRouteExpiredAssignmentCannotAcceptResult(t *testing.T) {
	s := store(t)
	landing, entry := strings.Repeat("a", 64), strings.Repeat("b", 64)
	d := artifact(1)
	if err := s.Put(Node{ID: "landing-a", CertificateID: landing, Desired: d}); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, landing, d)
	p := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entry, Request: p}}); err != nil {
		t.Fatal(err)
	}
	check := s.nodes[landing].Checks[p.EntryID]
	check.IssuedAt = time.Now().Add(-6 * time.Minute)
	s.nodes[landing].Checks[p.EntryID] = check
	p = check.Request
	r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Failure: "connect-or-tls"}
	if _, err := s.RouteExchange(context.Background(), entry, &r); err == nil {
		t.Fatal("expired result accepted")
	}
	pending, err := s.RouteExchange(context.Background(), entry, nil)
	if err != nil || len(pending) != 0 {
		t.Fatal("expired assignment issued")
	}
}
