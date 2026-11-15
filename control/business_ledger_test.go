package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestOwnedLedgerMigrationRetainsArchiveAndDurableTraffic(t *testing.T) {
	s, _, cert, _ := subscriptionFixture(t, false)
	dir := filepath.Dir(s.path)
	archivePath := businessArchivePathForTest(t, dir)
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope stagedImport
	if json.Unmarshal(businessBytes(t, s), &envelope) != nil || envelope.Version != 2 {
		t.Fatal("not forward migrated")
	}
	before := s.business.material
	started := time.Now().UTC().Add(-time.Hour)
	sampled := time.Now().UTC()
	r := quotaReceipt(s.nodes[cert].Desired, started, sampled, 12)
	if err = s.observeBusinessTrafficLocked(s.nodes[cert], r, sampled); err != nil {
		t.Fatal(err)
	}
	current := s.business.material.TrafficCounters["credential-example"]
	after, _ := os.ReadFile(archivePath)
	if !bytes.Equal(archive, after) {
		t.Fatal("traffic rewrote immutable history")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if loaded.business.material.TrafficCounters["credential-example"] != current || !bytes.Equal(before.RetainedSource, loaded.business.material.RetainedSource) {
		t.Fatal("durable traffic/history changed on reopen")
	}
	beforeJSON := businessBytes(t, loaded)
	if err = loaded.observeBusinessTrafficLocked(loaded.nodes[cert], r, sampled); err != nil || !bytes.Equal(beforeJSON, businessBytes(t, loaded)) {
		t.Fatal("duplicate sample was written twice", err)
	}
	// No pending/staged fallback is allowed when the referenced archive is lost.
	if err = os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}
	failed, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if failed.LoadBusiness(s.business.keyPath) == nil {
		t.Fatal("missing immutable archive accepted")
	}
}
func TestOwnedLedgerArchiveTamperFencesWithoutOverwriting(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	path := businessArchivePathForTest(t, filepath.Dir(s.path))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := businessBytes(t, s)
	plan := s.business.material.Plan.Accounts[0].Account.Plan
	plan.TotalBytes++
	if _, err = s.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err == nil || !s.business.faulted || !bytes.Equal(before, businessBytes(t, s)) {
		t.Fatal("archive tamper did not fence write", err)
	}
}
func TestOwnedLedgerInterruptedOrRolledBackMigrationFailsClosed(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	dir := filepath.Dir(s.path)
	archivePath := businessArchivePathForTest(t, dir)
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "business.json"), archive, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err == nil {
		t.Fatal("old ledger replay accepted in a migrated directory")
	}
	still, err := os.ReadFile(filepath.Join(dir, "business.json"))
	if err != nil || !bytes.Equal(still, archive) {
		t.Fatal("rejected migration changed original evidence")
	}

}

func TestOwnedLedgerInMemoryArchiveMutationCannotReachDisk(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	before := businessBytes(t, s)
	// A caller must not make a shared-slice edit look like an unchanged archive.
	raw := s.business.material.RetainedSource
	for i, b := range raw {
		if b == 's' {
			raw[i] = 't'
			break
		}
	}
	next := s.business.material
	if err := s.saveOwnedBusinessLocked(next); err == nil || !s.business.faulted || !bytes.Equal(before, businessBytes(t, s)) {
		t.Fatal("shared archive mutation bypassed fingerprint fence", err)
	}
}
func TestOwnedLedgerRejectsMismatchedPartialMigrationBeforeProjection(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	dir := filepath.Dir(s.path)
	archivePath := businessArchivePathForTest(t, dir)
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "business.json"), archive, 0600); err != nil {
		t.Fatal(err)
	}
	archive[len(archive)/2] ^= 1
	if err = os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	nodesBefore, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LoadBusiness(s.business.keyPath) == nil {
		t.Fatal("mismatched partial migration accepted")
	}
	nodesAfter, _ := os.ReadFile(s.path)
	if !bytes.Equal(nodesBefore, nodesAfter) {
		t.Fatal("refused migration changed node plans")
	}
}

func businessArchivePathForTest(t *testing.T, directory string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "business.json"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := checkpointEnvelope(raw)
	if err != nil || state.Version != 2 {
		t.Fatal("expected linked ledger", err)
	}
	return filepath.Join(directory, businessArchiveName(state.ArchiveSHA256))
}

func TestOrphanArchiveCannotStartOrReinitializeOwnedState(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	oldDir := filepath.Dir(s.path)
	raw, err := os.ReadFile(businessArchivePathForTest(t, oldDir))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	name := businessArchiveName(hex.EncodeToString(sum[:]))
	if err = os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(filepath.Join(directory, "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LoadBusiness("") == nil {
		t.Fatal("orphan archive started without an accounting key")
	}
	key, err := os.ReadFile(s.business.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LoadBusiness(s.business.keyPath) == nil {
		t.Fatal("orphan archive reconstructed missing live ledger")
	}
	if InitializeBusiness(directory, FreshBusiness{}, key) == nil {
		t.Fatal("orphan archive reinitialized")
	}
	transfer := bytes.Repeat([]byte{91}, 32)
	m := s.business.material
	m.Ownership = nil
	sealed, err := glivela.SealImportMaterial(m, transfer, s.business.snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if StageImport(directory, s.business.snapshotID, sealed, transfer, key) == nil {
		t.Fatal("orphan archive overwritten by staging")
	}
	pending, err := os.ReadFile(filepath.Join(oldDir, "business.pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "business.pending.json"), pending, 0600); err != nil {
		t.Fatal(err)
	}
	if AdoptStagedBusiness(directory, s.business.snapshotID, *s.business.material.Ownership, key) == nil {
		t.Fatal("old pending snapshot adopted over orphan archive")
	}
	for _, n := range []string{"business.json", "business.adoption.json"} {
		if _, err = os.Lstat(filepath.Join(directory, n)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused recovery created live state", n)
		}
	}
	after, _ := os.ReadFile(filepath.Join(directory, name))
	if !bytes.Equal(after, raw) {
		t.Fatal("orphan evidence changed")
	}
}

func TestHistoryRewritePublishesBoundV2WithoutChangingLiveLedger(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	directory := filepath.Dir(s.path)
	key, err := os.ReadFile(s.business.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	before, snapshot, fingerprint, err := ReadOwnedBusinessForHistory(directory, key)
	if err != nil {
		t.Fatal(err)
	}
	rawNodes, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	oldArchivePath := businessArchivePathForTest(t, directory)
	oldArchive, err := os.ReadFile(oldArchivePath)
	if err != nil {
		t.Fatal(err)
	}
	var history map[string]any
	if json.Unmarshal(before.RetainedSource, &history) != nil {
		t.Fatal("invalid fixture history")
	}
	history["history"] = []string{"remaining-history"}
	source, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	originalSnapshot := history["snapshotId"]
	history["snapshotId"] = "other-snapshot"
	invalidSource, _ := json.Marshal(history)
	history["snapshotId"] = originalSnapshot
	unchangedLedger := businessBytes(t, s)
	if ReplaceOwnedBusinessHistory(directory, key, fingerprint, invalidSource) == nil || !bytes.Equal(unchangedLedger, businessBytes(t, s)) {
		t.Fatal("history replacement accepted a different source identity")
	}
	next := before
	next.RetainedSource = source
	encrypted, err := glivela.SealImportMaterial(next, key, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := json.Marshal(stagedImport{Version: 1, SnapshotID: snapshot, Sealed: encrypted})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writeImmutableBusinessArchive(directory, proposal, nil); err != nil {
		t.Fatal(err)
	}
	// An interrupted archive-first proposal must leave the old commit readable.
	unchanged, _, _, err := ReadOwnedBusinessForHistory(directory, key)
	if err != nil || !bytes.Equal(unchanged.RetainedSource, before.RetainedSource) {
		t.Fatal("uncommitted proposal changed live history", err)
	}
	if err = ReplaceOwnedBusinessHistory(directory, key, fingerprint, source); err != nil {
		t.Fatal(err)
	}
	after, id, newFingerprint, err := ReadOwnedBusinessForHistory(directory, key)
	if err != nil || id != snapshot {
		t.Fatal(err)
	}
	if !bytes.Equal(after.RetainedSource, source) {
		t.Fatal("redacted source not committed")
	}
	strip := func(m glivela.ImportMaterial) []byte {
		m.RetainedSource = nil
		b, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	if !bytes.Equal(strip(before), strip(after)) {
		t.Fatal("history operation changed credentials, routes, watermarks or totals")
	}
	observedNodes, _ := os.ReadFile(s.path)
	if !bytes.Equal(rawNodes, observedNodes) {
		t.Fatal("history operation changed node policy")
	}
	if _, err = os.Stat(oldArchivePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old archive remained after successful commit")
	}
	currentBytes := businessBytes(t, s)
	if ReplaceOwnedBusinessHistory(directory, key, fingerprint, source) == nil || !bytes.Equal(currentBytes, businessBytes(t, s)) {
		t.Fatal("stale writer fence bypassed")
	}
	// Simulate interruption after commit but before deletion of the old archive.
	if _, err = writeImmutableBusinessArchive(directory, oldArchive, nil); err != nil {
		t.Fatal(err)
	}
	if err = ReplaceOwnedBusinessHistory(directory, key, newFingerprint, source); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentBytes, businessBytes(t, s)) {
		t.Fatal("retry resealed or replayed a ledger")
	}
	archives, err := filepath.Glob(filepath.Join(directory, businessArchivePrefix+"*.json"))
	if err != nil || len(archives) != 1 {
		t.Fatal("unreferenced archive cleanup incomplete", err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(strip(after), strip(loaded.business.material)) {
		t.Fatal("reopen changed live accounting")
	}
	// Authenticated ciphertext from a different capture must never be garbage-collected.
	foreign := after
	ownership := *after.Ownership
	ownership.CaptureSHA256 = glivela.Identity("different-capture")
	foreign.Ownership = &ownership
	sealedForeign, err := glivela.SealImportMaterial(foreign, key, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	foreignRaw, _ := json.Marshal(stagedImport{Version: 1, SnapshotID: snapshot, Sealed: sealedForeign})
	foreignDigest, err := writeImmutableBusinessArchive(directory, foreignRaw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ReplaceOwnedBusinessHistory(directory, key, newFingerprint, source) == nil || !bytes.Equal(currentBytes, businessBytes(t, s)) {
		t.Fatal("foreign archive identity did not block cleanup")
	}
	if _, err = os.Stat(filepath.Join(directory, businessArchiveName(foreignDigest))); err != nil {
		t.Fatal("foreign evidence removed", err)
	}
}
