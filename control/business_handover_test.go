package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func existingQuotaBusinessFixture(t *testing.T) (*Store, glivela.ImportMaterial, []byte, []byte) {
	t.Helper()
	source, d, cert, _ := subscriptionFixture(t, false)
	m := source.business.material
	m.Ownership = nil
	var header map[string]any
	if json.Unmarshal(m.RetainedSource, &header) != nil {
		t.Fatal("source header")
	}
	header["sourceSchema"] = 120
	m.RetainedSource, _ = json.Marshal(header)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(filepath.Join(dir, "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	q, desired, err := newEntryQuota(EntryQuotaSeed{CutoverAt: time.Now().UTC().Add(-time.Hour)}, d)
	if err != nil {
		t.Fatal(err)
	}
	node := source.nodes[cert]
	node.EntryQuota = q
	node.Desired = desired
	node.Receipt = nil
	node.ReportedAt = time.Time{}
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	transfer, key := bytes.Repeat([]byte{31}, 32), bytes.Repeat([]byte{32}, 32)
	sealed, err := glivela.SealImportMaterial(m, transfer, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if err := StageImport(dir, "snapshot-example", sealed, transfer, key); err != nil {
		t.Fatal(err)
	}
	bound, _, err := ReadStagedImport(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bound.Plan, m.Plan) || !reflect.DeepEqual(bound.TrafficCounters, m.TrafficCounters) || !bytes.Equal(bound.RetainedSource, m.RetainedSource) || !reflect.DeepEqual(bound.ProtocolSecrets, m.ProtocolSecrets) || !reflect.DeepEqual(bound.SubscriptionTokens, m.SubscriptionTokens) {
		t.Fatal("binding runtime changed imported identity or accounting")
	}
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	return s, bound, key, before
}

func TestExistingQuotaBusinessAdoptionPreservesNodesAndCounters(t *testing.T) {
	s, m, key, before := existingQuotaBusinessFixture(t)
	dir := filepath.Dir(s.path)
	proof := ownershipFixture(m)
	if err := AdoptStagedBusiness(dir, "snapshot-example", proof, key); err != nil {
		t.Fatal(err)
	}
	current, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for cert, node := range current.nodes {
		old := s.nodes[cert]
		old.EntryQuota = nil
		if !reflect.DeepEqual(old, node) {
			t.Fatal("node identity, configuration or receipt changed")
		}
	}
	keyPath := filepath.Join(dir, "business.key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := current.LoadBusiness(keyPath); err != nil {
		t.Fatal(err)
	}
	for cert, node := range current.nodes {
		old := s.nodes[cert]
		old.EntryQuota = nil
		if !reflect.DeepEqual(old, node) {
			t.Fatal("loading owned business changed the enrolled runtime")
		}
	}
	if !reflect.DeepEqual(current.business.material.Plan, m.Plan) || !reflect.DeepEqual(current.business.material.TrafficCounters, m.TrafficCounters) {
		t.Fatal("account ledger changed")
	}
	owned, err := os.ReadFile(filepath.Join(dir, "business.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the precise crash window: owned data durable, node commit not yet
	// acknowledged. Only offline re-adoption may finish it, not a runtime fallback.
	if err := os.WriteFile(s.path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "business.nodes.applied.json")); err != nil {
		t.Fatal(err)
	}
	if err := AdoptStagedBusiness(dir, "snapshot-example", proof, key); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "business.json"))
	if !bytes.Equal(owned, after) {
		t.Fatal("retry rewrote owned ledger")
	}
	// A restored old quota file after acknowledgement must never silently replay.
	if err := os.WriteFile(s.path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if AdoptStagedBusiness(dir, "snapshot-example", proof, key) == nil {
		t.Fatal("retired quota replay accepted")
	}
}

func TestExistingQuotaBusinessRejectsPolicyConflictBeforeOwnership(t *testing.T) {
	s, m, key, _ := existingQuotaBusinessFixture(t)
	dir := filepath.Dir(s.path)
	for cert, node := range s.nodes {
		node.EntryQuota = node.EntryQuota.clone()
		node.EntryQuota.TotalBytes = 123
		s.nodes[cert] = node
	}
	if err := s.commit(s.nodes); err != nil {
		t.Fatal(err)
	}
	if AdoptStagedBusiness(dir, "snapshot-example", ownershipFixture(m), key) == nil {
		t.Fatal("conflicting quota accepted")
	}
	for _, name := range []string{"business.json", "business.adoption.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("rejected preflight wrote ownership")
		}
	}
}

func TestOwnedProjectionDoesNotReapplyAcknowledgementMetadata(t *testing.T) {
	s, _, cert, _ := subscriptionFixture(t, true)
	node := s.nodes[cert]
	node.Desired = node.Desired.clone()
	for i := range node.Desired.Entry.Grants {
		g := &node.Desired.Entry.Grants[i]
		g.AppliedRev = g.DesiredRev
		g.RuntimeGood = true
	}
	s.nodes[cert] = node
	next, changed, err := projectBusinessEntries(s.nodes, s.business.material, time.Now())
	if err != nil || changed || !reflect.DeepEqual(next, s.nodes) {
		t.Fatal("matching runtime was needlessly revised", err)
	}
}
