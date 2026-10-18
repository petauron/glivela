package control

import (
	"context"
	"testing"
	"time"

	"github.com/petauron/glivela/landing"
)

func TestEntryMonitorLivenessDoesNotTreatOneBlockedPeerAsProcessFailure(t *testing.T) {
	desired := routedEntryArtifact(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := &entryMonitorGroup{cancel: cancel, done: make(chan struct{}), desired: desired.clone(), active: map[string]bool{"landing-example": true}, statuses: map[string]landing.MonitorStatus{"landing-example": {Revision: desired.Revision, State: "blocked", Reason: "probe-failed"}}}
	d := &EntryDriver{}
	d.monitors.group = g
	if err := d.monitors.verify(desired); err != nil {
		t.Fatal("ordinary peer failure became global runtime failure", err)
	}
	status := d.PeerStatus()
	status["landing-example"] = landing.MonitorStatus{State: "healthy"}
	if d.PeerStatus()["landing-example"].State != "blocked" {
		t.Fatal("caller changed owned peer status")
	}
	g.active["landing-example"] = false
	if d.monitors.verify(desired) == nil {
		t.Fatal("terminated peer monitor counted as active")
	}
	go func() { <-ctx.Done(); close(g.done) }()
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.PeerStatus()) != 0 {
		t.Fatal("retired monitor evidence retained")
	}
}

func TestEntryMonitorCloseWaitsForOldOwnershipToEnd(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := &entryMonitorGroup{cancel: cancel, done: make(chan struct{})}
	m := entryMonitors{group: g}
	short, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if m.close(short) == nil || m.group != g {
		t.Fatal("unfinished monitor group abandoned")
	}
	close(g.done)
	if err := m.close(context.Background()); err != nil || m.group != nil {
		t.Fatal("later close could not finish same group", err)
	}
}
