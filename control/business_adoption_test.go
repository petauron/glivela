package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
)

func ownershipFixture(m glivela.ImportMaterial) glivela.BusinessOwnership {
	return glivela.BusinessOwnership{SourceSHA256: m.SourceSHA256, CaptureSHA256: glivela.Identity("capture-example"), PreviousWriterID: strings.Repeat("a", 64), StoppedAt: "2026-10-19T02:00:00Z", CapturedAt: "2026-10-19T02:01:00Z"}
}

func TestBusinessAdoptionRetainsDataAndDoesNotReplayStaging(t *testing.T) {
	s, keyPath, original := stagedBusinessStore(t)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(s.path)
	pending := filepath.Join(directory, "business.pending.json")
	before, err := os.ReadFile(pending)
	if err != nil {
		t.Fatal(err)
	}
	ownership := ownershipFixture(original)
	if err := AdoptStagedBusiness(directory, "snapshot-example", ownership, key); err != nil {
		t.Fatal(err)
	}
	owned, id, err := readOwnedBusiness(directory, key)
	if err != nil || id != "snapshot-example" || owned.Ownership == nil || *owned.Ownership != ownership {
		t.Fatal("ownership commit invalid", err)
	}
	owned.Ownership = nil
	if !reflect.DeepEqual(original, owned) {
		t.Fatal("adoption changed identities, configuration, history, cycles or ledger")
	}
	after, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery checkpoint changed", err)
	}
	activePath := filepath.Join(directory, "business.json")
	active, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := AdoptStagedBusiness(directory, "snapshot-example", ownership, key); err != nil {
		t.Fatal(err)
	}
	retry, err := os.ReadFile(activePath)
	if err != nil || !bytes.Equal(active, retry) {
		t.Fatal("adoption retry resealed or rewrote owned data", err)
	}
	if err := s.LoadBusiness(keyPath); err != nil {
		t.Fatal(err)
	}
	view := s.Business()
	if view.State != "owned-unverified" || view.SnapshotID != "snapshot-example" || view.Accounts[0].Account != original.Plan.Accounts[0].Account || len(s.nodes) != 0 {
		t.Fatal("data ownership manufactured runtime health or changed accounts")
	}
	if _, _, err := ReadStagedImport(directory, key); err == nil {
		t.Fatal("stale staged data remained a current-state reader")
	}
	transfer := bytes.Repeat([]byte{29}, 32)
	sealed, err := glivela.SealImportMaterial(original, transfer, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if StageImport(directory, "snapshot-example", sealed, transfer, key) == nil {
		t.Fatal("staging reinitialized owned business")
	}
	if _, _, err := readOwnedBusiness(directory, key); err != nil {
		t.Fatal("refused staging changed owned data", err)
	}
}

func TestBusinessAdoptionRejectsChangedEvidenceOrRunningController(t *testing.T) {
	for _, fault := range []string{"source", "snapshot", "proof", "time", "lease"} {
		t.Run(fault, func(t *testing.T) {
			s, keyPath, m := stagedBusinessStore(t)
			key, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Dir(s.path)
			o := ownershipFixture(m)
			snapshot := "snapshot-example"
			switch fault {
			case "source":
				o.SourceSHA256 = glivela.Identity("different-source")
			case "snapshot":
				snapshot = "different-snapshot"
			case "proof":
				o.CaptureSHA256 = "not-a-digest"
			case "time":
				o.CapturedAt = "2026-10-18T00:00:00Z"
			case "lease":
				unlock, err := LockDirectory(directory)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			}
			if AdoptStagedBusiness(directory, snapshot, o, key) == nil {
				t.Fatal("unverified or concurrent adoption accepted")
			}
			if _, err := os.Stat(filepath.Join(directory, "business.json")); !os.IsNotExist(err) {
				t.Fatal("refused adoption wrote owned state")
			}
		})
	}
}

func TestOwnedBusinessNeverFallsBackToPendingRecovery(t *testing.T) {
	for _, fault := range []string{"corrupt", "public", "symlink", "missing-key", "unauthenticated-ownership", "missing-ownership", "lost-owned-file", "lost-intent", "corrupt-intent"} {
		t.Run(fault, func(t *testing.T) {
			s, keyPath, m := stagedBusinessStore(t)
			key, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Dir(s.path)
			if err := AdoptStagedBusiness(directory, "snapshot-example", ownershipFixture(m), key); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "business.json")
			switch fault {
			case "lost-owned-file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "lost-intent":
				if err := os.Remove(filepath.Join(directory, "business.adoption.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt-intent":
				if err := os.WriteFile(filepath.Join(directory, "business.adoption.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				keyPath = ""
			case "unauthenticated-ownership":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var object map[string]json.RawMessage
				if json.Unmarshal(raw, &object) != nil {
					t.Fatal("bad fixture")
				}
				object["ownership"] = json.RawMessage(`{"accepted":true}`)
				raw, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-ownership":
				raw, err := os.ReadFile(filepath.Join(directory, "business.pending.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if s.LoadBusiness(keyPath) == nil || s.business != nil {
				t.Fatal("damaged ownership fell back to valid recovery data")
			}
		})
	}
}

func TestTransferArchiveCannotSetOwnedAuthority(t *testing.T) {
	s, keyPath, m := stagedBusinessStore(t)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	o := ownershipFixture(m)
	m.Ownership = &o
	transfer := bytes.Repeat([]byte{30}, 32)
	sealed, err := glivela.SealImportMaterial(m, transfer, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if StageImport(filepath.Dir(s.path), "snapshot-example", sealed, transfer, key) == nil {
		t.Fatal("transfer archive granted authority")
	}
}

func TestLostOwnedDataCannotBeRecreatedByReplayingAdoption(t *testing.T) {
	s, keyPath, m := stagedBusinessStore(t)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(s.path)
	o := ownershipFixture(m)
	if err := AdoptStagedBusiness(directory, "snapshot-example", o, key); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "business.json")); err != nil {
		t.Fatal(err)
	}
	if AdoptStagedBusiness(directory, "snapshot-example", o, key) == nil {
		t.Fatal("lost live state was recreated from stale staging")
	}
	if _, err := os.Stat(filepath.Join(directory, "business.json")); !os.IsNotExist(err) {
		t.Fatal("rejected replay wrote old account or usage values")
	}
}
