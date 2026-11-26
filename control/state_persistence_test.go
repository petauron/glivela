package control

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestSteadyStateExchangeCoalescesNodesCommitsAndPreservesTransitions(t *testing.T) {
	s, d, entryCert, _ := subscriptionFixture(t, true)
	started := time.Now().UTC().Add(-time.Hour)
	t1 := time.Now().UTC().Add(-10 * time.Second)

	obs1 := healthyEntryObservation(d, t1)
	obs1.Traffic = quotaReceipt(d, started, t1, 10).Traffic
	if _, err := s.Exchange(context.Background(), entryCert, &obs1); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("initial report was not immediately committed")
	}
	nodesAfterFirst, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	businessAfterFirst := businessBytes(t, s)

	// Steady-state healthy heartbeat with newer timestamps and traffic delta must
	// persist business.json immediately while coalescing nodes.json writes.
	t2 := t1.Add(2 * time.Second)
	obs2 := obs1.clone()
	obs2.EntryHealth.SampledAt = t2
	obs2.Traffic = quotaReceipt(d, started, t2, 25).Traffic
	if _, err := s.Exchange(context.Background(), entryCert, &obs2); err != nil {
		t.Fatal(err)
	}
	if !s.nodesDirty {
		t.Fatal("steady-state heartbeat unexpectedly committed nodes.json")
	}
	if !s.nodes[entryCert].EntryHealthBarrierAt.Equal(t2) {
		t.Fatal("in-memory barrier timestamp did not advance")
	}
	nodesAfterSecond, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nodesAfterFirst, nodesAfterSecond) {
		t.Fatal("steady-state heartbeat rewrote nodes.json on disk")
	}
	if bytes.Equal(businessAfterFirst, businessBytes(t, s)) {
		t.Fatal("traffic delta was not durably written to business.json")
	}

	// BackupController must flush dirty heartbeats before reading nodes.json.
	if err := s.BackupController(time.Now().UTC()); err != nil {
		t.Fatal("backup failed with dirty steady-state heartbeats:", err)
	}
	if s.nodesDirty {
		t.Fatal("backup did not flush dirty nodes state")
	}

	// Flush persists coalesced steady-state heartbeats cleanly for shutdown.
	t3 := t2.Add(2 * time.Second)
	obs3 := obs1.clone()
	obs3.EntryHealth.SampledAt = t3
	obs3.Traffic = quotaReceipt(d, started, t3, 25).Traffic
	if _, err := s.Exchange(context.Background(), entryCert, &obs3); err != nil {
		t.Fatal(err)
	}
	if !s.nodesDirty {
		t.Fatal("second steady-state heartbeat unexpectedly committed")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("Flush left nodesDirty set")
	}
	reopened, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.nodes[entryCert].EntryHealthBarrierAt.Equal(t3) {
		t.Fatal("Flush did not persist coalesced heartbeat timestamp")
	}

	// Periodic flush window commits steady-state heartbeats once interval elapses.
	s.nodesCommittedAt = time.Now().UTC().Add(-nodesHeartbeatFlushInterval - time.Second)
	t4 := t3.Add(time.Second)
	obs4 := obs1.clone()
	obs4.EntryHealth.SampledAt = t4
	obs4.Traffic = quotaReceipt(d, started, t4, 25).Traffic
	if _, err := s.Exchange(context.Background(), entryCert, &obs4); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("expired heartbeat flush window did not commit nodes.json")
	}

	// Health degradation (healthy -> blocked) must commit immediately.
	t5 := t4.Add(time.Second)
	obs5 := obs1.clone()
	obs5.EntryHealth.SampledAt = t5
	obs5.Traffic = quotaReceipt(d, started, t5, 25).Traffic
	if _, err := s.Exchange(context.Background(), entryCert, &obs5); err != nil {
		t.Fatal(err)
	}
	if !s.nodesDirty {
		t.Fatal("pre-transition steady heartbeat unexpectedly committed")
	}
	t6 := t5.Add(time.Second)
	blocked := obs5.clone()
	blocked.EntryHealth.SampledAt = t6
	peer := blocked.EntryHealth.Peers["landing-example"]
	peer.Status.State, peer.Status.Reason, peer.Status.Stage = "blocked", "business_check_failed", "business_check"
	peer.Status.AllowedUntil = time.Time{}
	blocked.EntryHealth.Peers["landing-example"] = peer
	if _, err := s.Exchange(context.Background(), entryCert, &blocked); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("blocked health transition did not commit immediately")
	}
	reopenedBlocked, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedBlocked.nodes[entryCert].Receipt.EntryHealth.Peers["landing-example"].Status.State != "blocked" {
		t.Fatal("blocked state not persisted on disk")
	}

	// Recovery (blocked -> healthy) and readiness loss (nil receipt) commit immediately.
	t7 := t6.Add(time.Second)
	recovered := obs1.clone()
	recovered.EntryHealth.SampledAt = t7
	recovered.Traffic = quotaReceipt(d, started, t7, 25).Traffic
	if _, err := s.Exchange(context.Background(), entryCert, &recovered); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("recovery transition did not commit immediately")
	}
	if _, err := s.Exchange(context.Background(), entryCert, nil); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("readiness loss did not commit immediately")
	}
	reopenedCleared, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedCleared.nodes[entryCert].Receipt != nil {
		t.Fatal("cleared receipt not persisted on disk")
	}
}
