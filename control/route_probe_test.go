package control

import (
	glivela "github.com/petauron/glivela"
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

func TestSharedPublicRoutePortIsExactAndCannotFallBack(t *testing.T) {
	d := routedEntryArtifact(t)
	plan := *d.Entry
	transport := glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw==", PublicAddress: "8.8.8.8", Port: 24000}
	plan.Peers[0].Port, plan.Peers[0].Transport = 24000, transport
	updated, err := NewEntryDesired(plan, *d.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated.Config), `"port":24000`) {
		t.Fatal("server dialer lost explicit port")
	}
	p := RouteProbe{AttemptID: "attempt-example", SnapshotID: "snapshot-a", EntryID: "entry-example", LandingID: "landing-example", Revision: 1, ConfigSHA256: strings.Repeat("a", 64), Transport: transport, SOCKSAddress: "8.8.8.8:24000", Target: "https://check.example.invalid/exit", ExpectedExit: "8.8.4.4"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"8.8.8.8:1080", "100.64.0.2:24000", "1.1.1.1:24000"} {
		bad := p
		bad.SOCKSAddress = address
		if bad.Validate() == nil {
			t.Fatal("accepted a different endpoint", address)
		}
	}
	plan.Peers[0].Port = 1080
	if _, err := NewEntryDesired(plan, *d.EntryNetwork); err == nil {
		t.Fatal("accepted mismatched peer port")
	}
}
