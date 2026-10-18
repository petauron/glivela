package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type routeClientFixture struct {
	check   RouteProbe
	report  *RouteProbeResult
	lostAck bool
}

func (f *routeClientFixture) RouteExchange(_ context.Context, r *RouteProbeResult) ([]RouteProbe, error) {
	if r != nil {
		copy := *r
		f.report = &copy
		if f.lostAck {
			return nil, errors.New("lost response")
		}
	}
	if f.report != nil {
		return nil, nil
	}
	return []RouteProbe{f.check}, nil
}
func TestRouteRunnerReportsFailureAndDoesNotRepeatCommittedAttempt(t *testing.T) {
	f := &routeClientFixture{lostAck: true, check: RouteProbe{AttemptID: "attempt-a", SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: 1, ConfigSHA256: strings.Repeat("a", 64), SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}}
	calls := 0
	r := RouteRunner{Client: f, probe: func(ctx context.Context, p RouteProbe) (RouteProbeResult, error) {
		calls++
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("unbounded probe")
		}
		return RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Failure: "connect-or-tls"}, errors.New("connection failed")
	}}
	if r.Step(context.Background()) == nil {
		t.Fatal("lost acknowledgement ignored")
	}
	if f.report == nil || f.report.Passed || f.report.Failure != "connect-or-tls" {
		t.Fatal("failure not reported")
	}
	if err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("completed attempt repeated")
	}
}
