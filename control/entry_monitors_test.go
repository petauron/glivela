package control

import (
	"context"
	"github.com/petauron/glivela/landing"
	"testing"
	"time"
)

func TestEntryStartupProofPersistsUntilReconfiguration(t *testing.T) {
	desired := routedEntryArtifact(t)
	d := &EntryDriver{}
	d.monitors.group = &entryMonitorGroup{desired: desired.clone(), statuses: map[string]landing.MonitorStatus{"landing-example": {Revision: desired.Revision, State: "healthy", Stage: "startup", CheckedAt: time.Now().Add(-24 * time.Hour)}}}
	if err := d.monitors.verify(desired); err != nil {
		t.Fatal(err)
	}
	status := d.PeerStatus()
	delete(status, "landing-example")
	if len(d.PeerStatus()) != 1 {
		t.Fatal("caller mutated startup evidence")
	}
	changed := desired.clone()
	changed.Revision++
	if d.monitors.verify(changed) == nil {
		t.Fatal("new revision reused old acceptance")
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.monitors.verify(desired) == nil {
		t.Fatal("closed owner retained acceptance")
	}
}
