package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

type adoptionFixture struct {
	data, backup, state string
	storage             []byte
	material            glivela.ImportMaterial
	container           oldCenterContainer
}

func prepareAdoptionFixture(t *testing.T, database, key []byte, m glivela.ImportMaterial, snapshot string) adoptionFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := adoptionFixture{data: filepath.Join(root, "source"), backup: filepath.Join(root, "backup"), state: filepath.Join(root, "controller"), storage: bytes.Repeat([]byte{31}, 32), material: m}
	for _, dir := range []string{f.data, f.state} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string][]byte{"center.db": database, "center.key": key} {
		if err := os.WriteFile(filepath.Join(f.data, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.container = stoppedContainerFixture(f.data)
	f.container.State.StartedAt = time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	f.container.State.FinishedAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	inspect := func(context.Context) ([]oldCenterContainer, error) { return []oldCenterContainer{f.container}, nil }
	if err := captureFinal(context.Background(), f.data, f.backup, f.container.ID, inspect); err != nil {
		t.Fatal(err)
	}
	transfer := bytes.Repeat([]byte{32}, 32)
	sealed, err := glivela.SealImportMaterial(m, transfer, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.StageImport(f.state, snapshot, sealed, transfer, f.storage); err != nil {
		t.Fatal(err)
	}
	return f
}

func syntheticAdoptionFixture(t *testing.T) adoptionFixture {
	t.Helper()
	database := []byte("anonymous persisted source fixture")
	sum := sha256.Sum256(database)
	a := completeEndpointArchiveFixture(t)
	a.SourceSHA256 = hex.EncodeToString(sum[:])
	m, err := importMaterial(a)
	if err != nil {
		t.Fatal(err)
	}
	return prepareAdoptionFixture(t, database, bytes.Repeat([]byte{7}, 32), m, "snapshot-example")
}

func TestFinalAdoptionRejectsChangedCaptureSourceOrWriter(t *testing.T) {
	for _, fault := range []string{"running", "restarted", "source", "backup", "key", "shared-key", "proof", "snapshot", "changed-during-inspection", "active-controller"} {
		t.Run(fault, func(t *testing.T) {
			f := syntheticAdoptionFixture(t)
			snapshot := "snapshot-example"
			write := func(path string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "running":
				f.container.State.Running = true
			case "restarted":
				f.container.State.StartedAt = time.Now().UTC().Add(-90 * time.Minute).Format(time.RFC3339Nano)
			case "source":
				write(filepath.Join(f.data, "center.db"), []byte("changed-source"))
			case "backup":
				write(filepath.Join(f.backup, "center.db"), []byte("changed-backup"))
			case "key":
				write(filepath.Join(f.data, "center.key"), bytes.Repeat([]byte{8}, 32))
			case "shared-key":
				f.storage = bytes.Repeat([]byte{7}, 32)
			case "proof":
				write(filepath.Join(f.backup, "capture.json"), []byte(`{"version":1}`))
			case "snapshot":
				snapshot = "another-snapshot"
			case "active-controller":
				unlock, err := control.LockDirectory(f.state)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			}
			calls := 0
			inspect := func(context.Context) ([]oldCenterContainer, error) {
				calls++
				if calls == 2 && fault == "changed-during-inspection" {
					write(filepath.Join(f.data, "center.db"), []byte("changed-after-first-read"))
				}
				return []oldCenterContainer{f.container}, nil
			}
			if adoptFinal(context.Background(), f.data, f.backup, f.state, snapshot, f.storage, inspect) == nil {
				t.Fatal("invalid final handover committed")
			}
			if _, err := os.Stat(filepath.Join(f.state, "business.json")); !os.IsNotExist(err) {
				t.Fatal("failed handover created owned state")
			}
		})
	}
}

func TestFinalAdoptionLoadsOwnStateWithoutManufacturingHealth(t *testing.T) {
	f := syntheticAdoptionFixture(t)
	inspect := func(context.Context) ([]oldCenterContainer, error) { return []oldCenterContainer{f.container}, nil }
	if err := adoptFinal(context.Background(), f.data, f.backup, f.state, "snapshot-example", f.storage, inspect); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.state, "business.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := adoptFinal(context.Background(), f.data, f.backup, f.state, "snapshot-example", f.storage, inspect); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeat adoption rewrote data", err)
	}
	assertOwnedMaterial(t, f.state, "snapshot-example", f.storage, f.material)
}

func assertOwnedMaterial(t *testing.T, directory, snapshot string, key []byte, original glivela.ImportMaterial) {
	t.Helper()
	raw, err := privateFile(filepath.Join(directory, "business.json"), 90<<20)
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Version    int
		SnapshotID string
		Sealed     []byte
	}
	if json.Unmarshal(raw, &frame) != nil || frame.Version != 1 || frame.SnapshotID != snapshot {
		t.Fatal("invalid owned checkpoint")
	}
	m, err := glivela.OpenImportMaterial(frame.Sealed, key, snapshot)
	if err != nil || m.Ownership == nil {
		t.Fatal("missing sealed ownership", err)
	}
	m.Ownership = nil
	canonical, err := glivela.SealImportMaterial(original, key, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want, err := glivela.OpenImportMaterial(canonical, key, snapshot)
	if err != nil || !reflect.DeepEqual(m, want) {
		t.Fatal("final handover changed original data", err)
	}
	keyPath := filepath.Join(directory, "storage.key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := control.OpenStore(filepath.Join(directory, "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LoadBusiness(keyPath); err != nil {
		t.Fatal(err)
	}
	if s.Business().State != "owned-unverified" {
		t.Fatal("data handover claimed runtime/route acceptance")
	}
}

func TestRealLegacyFinalCaptureExportAndAdoption(t *testing.T) {
	dir := os.Getenv("GLIVELA_ACCOUNT_FIXTURE_DIR")
	if dir == "" {
		t.Skip("anonymous old-source fixture not supplied")
	}
	database, err := privateFile(filepath.Join(dir, "center.db"), maxSnapshotBytes)
	if err != nil {
		t.Fatal("fixture database unavailable")
	}
	key, err := privateFile(filepath.Join(dir, "center.key"), 32)
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	defer clear(key)
	transfer, err := privateFile(filepath.Join(dir, "transfer.key"), 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(transfer)
	archiveBytes, err := privateFile(filepath.Join(dir, "legacy.sealed"), maxSnapshotBytes+64)
	if err != nil {
		t.Fatal(err)
	}
	const snapshot = "actual-accounts-example"
	a, err := openArchive(archiveBytes, transfer, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	m, err := importMaterial(a)
	if err != nil {
		t.Fatal(err)
	}
	f := prepareAdoptionFixture(t, database, key, m, snapshot)
	transferPath := filepath.Join(f.state, "transfer.key")
	storagePath := filepath.Join(f.state, "storage.key")
	if err := os.WriteFile(transferPath, bytes.Repeat([]byte{32}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storagePath, f.storage, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(f.backup, "final.sealed")
	if err := export(context.Background(), filepath.Join(f.backup, "center.db"), filepath.Join(f.backup, "center.key"), transferPath, snapshot, output); err != nil {
		t.Fatal("real final snapshot export failed", err)
	}
	if err := stageImportCommand([]string{"-archive", output, "-snapshot", snapshot, "-state-directory", f.state, "-transfer-key", transferPath, "-storage-key", storagePath}); err != nil {
		t.Fatal("real final snapshot staging differs", err)
	}
	inspect := func(context.Context) ([]oldCenterContainer, error) { return []oldCenterContainer{f.container}, nil }
	if err := adoptFinal(context.Background(), f.data, f.backup, f.state, snapshot, f.storage, inspect); err != nil {
		t.Fatal("real final data adoption failed", err)
	}
	assertOwnedMaterial(t, f.state, snapshot, f.storage, m)
	after, err := privateFile(filepath.Join(dir, "center.db"), maxSnapshotBytes)
	if err != nil || !bytes.Equal(database, after) {
		t.Fatal("original frozen source changed", err)
	}
}
