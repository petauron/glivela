package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryCheckpointRejectsChangedResources(t *testing.T) {
	for _, kind := range []string{"valid", "identity", "config", "journal", "program", "extra", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, _ := legacyFixture(t)
			snapshot, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			backups := t.TempDir()
			if err := os.Chmod(backups, 0700); err != nil {
				t.Fatal(err)
			}
			path, err := backupLegacyLanding(backups, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "identity":
				snapshot.NodeID = "another-node"
			case "config":
				r := snapshot.Files[legacyLandingFiles[0]]
				r.Contents = []byte("changed")
				snapshot.Files[legacyLandingFiles[0]] = r
			case "journal":
				snapshot.Journal = []byte(`{}`)
			case "program":
				// Simulate an owner replacing the retained executable. Ordinary
				// writes are correctly denied by its production 0500 mode.
				if err := os.Chmod(filepath.Join(filepath.Dir(path), "recovery-program"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "recovery-program"), []byte("changed"), 0500); err != nil {
					t.Fatal(err)
				}
			case "extra":
				snapshot.Files["/etc/unowned"] = LegacyOwnedFile{}
			}
			raw, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			}
			_, program, err := loadLegacyBackup(path, "node-example", uint32(os.Getuid()))
			if program != nil {
				program.Close()
			}
			if kind == "valid" && err != nil {
				t.Fatal(err)
			}
			if kind != "valid" && err == nil {
				t.Fatal("unsafe recovery checkpoint accepted")
			}
		})
	}
}
