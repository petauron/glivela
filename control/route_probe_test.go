package control

import (
	"strings"
	"testing"
)

func TestRouteProbeScope(t *testing.T) {
	p := RouteProbe{AttemptID: "attempt-example", SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: 1, ConfigSHA256: strings.Repeat("a", 64), SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RouteProbe){
		func(p *RouteProbe) { p.SOCKSAddress = "203.0.113.1:1080" },
		func(p *RouteProbe) { p.Target = "http://example.invalid/" },
		func(p *RouteProbe) { p.Target = "https://password@example.invalid/" },
		func(p *RouteProbe) { p.Target = "https://example.invalid/?token=private" },
		func(p *RouteProbe) { p.ExpectedExit = "192.168.1.1" },
		func(p *RouteProbe) { p.Revision = 0 },
		func(p *RouteProbe) { p.SnapshotID = "" },
	} {
		changed := p
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid route acceptance request allowed")
		}
	}
}
