package control

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
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

func TestSteadyStateLandingCoalescingAndEntryNilHealthCommits(t *testing.T) {
	s, d, entryCert, landingCert := subscriptionFixture(t, true)
	landingDesired := s.nodes[landingCert].Desired

	// Landing steady-state heartbeats coalesce, while ManagementIdentity changes commit immediately.
	landingObs := Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: landingDesired.Revision, ConfigSHA256: landingDesired.ConfigSHA256, RuntimeReady: true}}
	if _, err := s.Exchange(context.Background(), landingCert, &landingObs); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("initial landing report did not commit immediately")
	}
	nodesBefore, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(context.Background(), landingCert, &landingObs); err != nil {
		t.Fatal(err)
	}
	if !s.nodesDirty {
		t.Fatal("steady-state landing heartbeat unexpectedly committed")
	}
	nodesAfter, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nodesBefore, nodesAfter) {
		t.Fatal("steady-state landing heartbeat rewrote nodes.json")
	}
	withIdentity := landingObs.clone()
	withIdentity.ManagementIdentity = &landing.PeerIdentity{ID: "landing-mesh", PublicKey: "nodekey:landing-mesh", Address: landingDesired.Landing.Address}
	if _, err := s.Exchange(context.Background(), landingCert, &withIdentity); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("landing management identity change did not commit immediately")
	}
	reopened, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.nodes[landingCert].Receipt == nil || reopened.nodes[landingCert].Receipt.ManagementIdentity == nil || *reopened.nodes[landingCert].Receipt.ManagementIdentity != *withIdentity.ManagementIdentity {
		t.Fatal("landing management identity was not persisted")
	}
	if _, err := s.Exchange(context.Background(), landingCert, &withIdentity); err != nil {
		t.Fatal(err)
	}
	if !s.nodesDirty {
		t.Fatal("steady-state landing heartbeat with unchanged management identity unexpectedly committed")
	}

	// Consecutive entry exchanges with nil or rejected EntryHealth must always commit
	// immediately so the advancing EntryHealthBarrierAt survives an unclean restart.
	nilHealth := Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, RuntimeReady: true}}
	if _, err := s.Exchange(context.Background(), entryCert, &nilHealth); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("first nil-health entry exchange did not commit")
	}
	futureHealth := healthyEntryObservation(d, time.Now().UTC().Add(time.Hour))
	if _, err := s.Exchange(context.Background(), entryCert, &futureHealth); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("consecutive nil/rejected-health entry exchange was coalesced")
	}
	expectedBarrier := s.nodes[entryCert].EntryHealthBarrierAt
	reopenedEntry, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopenedEntry.nodes[entryCert].EntryHealthBarrierAt.Equal(expectedBarrier) {
		t.Fatal("advancing entry replay barrier was not persisted on consecutive nil-health exchange")
	}
}

func TestBackupControllerFlushesDirtyNodesBeforeAvailabilitySnapshot(t *testing.T) {
	s, _, entryCert, _ := subscriptionFixture(t, true)
	now := time.Now().UTC()
	next := s.business.material
	next.Endpoints = slices.Clone(next.Endpoints)
	next.Endpoints[0].TotalBytes = 100
	next.Endpoints[0].UsedBytes = 100
	next.Endpoints[0].QuotaAppliedEnabled = false
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAvailability("entry-a", "maintenance", now.Add(time.Hour), s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileOwnedEntriesLocked(now); err != nil {
		t.Fatal(err)
	}
	d := s.nodes[entryCert].Desired
	t1 := now.Add(-4 * time.Second)
	obs1 := healthyEntryObservation(d, t1)
	if _, err := s.Exchange(context.Background(), entryCert, &obs1); err != nil {
		t.Fatal(err)
	}
	if s.nodesDirty {
		t.Fatal("initial exchange did not commit")
	}
	obs2 := obs1.clone()
	obs2.EntryHealth.SampledAt = t1.Add(2 * time.Second)
	if _, err := s.Exchange(context.Background(), entryCert, &obs2); err != nil {
		t.Fatal(err)
	}
	if !s.nodesDirty {
		t.Fatal("steady-state exchange while maintenance suspension active did not coalesce")
	}
	// Expire the maintenance suspension so BackupController's flush triggers
	// retainQuotaSuspensions and advances s.availability.Revision.
	expired := s.availability.Nodes["entry-a"]
	expired.ChangedAt = now.Add(-2 * time.Second)
	expired.ResumeAt = now.Add(-time.Second)
	s.availability.Nodes["entry-a"] = expired
	revBefore := s.availability.Revision
	if err := s.BackupController(time.Now().UTC()); err != nil {
		t.Fatal("BackupController failed:", err)
	}
	if s.nodesDirty {
		t.Fatal("BackupController left nodesDirty set")
	}
	if s.availability.Revision != revBefore+1 {
		t.Fatalf("expected availability revision to advance during flush (%d -> %d)", revBefore, s.availability.Revision)
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(s.path), "controller-backup-*.gcm"))
	if err != nil || len(paths) != 1 {
		t.Fatal("backup snapshot missing", err)
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "restored")
	if err := RestoreControllerBackup(paths[0], s.business.keyPath, destination); err != nil {
		t.Fatal("RestoreControllerBackup rejected flushed availability/nodes snapshot:", err)
	}
	restored, err := OpenStore(filepath.Join(destination, "nodes.json"))
	if err != nil {
		t.Fatal("OpenStore rejected restored snapshot:", err)
	}
	if restored.availability.Revision != s.availability.Revision || restored.nodes[entryCert].AvailabilityRevision != s.availability.Revision {
		t.Fatal("restored availability revision does not match flushed nodes snapshot")
	}
}
