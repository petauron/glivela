package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func legacyFixture(t *testing.T) (string, map[string]any) {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{}
	for _, path := range legacyLandingFiles {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		raw := []byte("anonymous fixture " + path)
		if err := os.WriteFile(full, raw, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		files[path] = hex.EncodeToString(digest[:])
	}
	metadata := map[string]any{"nodeId": "node-example", "uid": 12345, "revision": 7, "files": files, "policy": map[string]any{"example": true}, "removed": false}
	writeLegacyJournal(t, root, metadata)
	return root, metadata
}

func writeLegacyJournal(t *testing.T, root string, metadata map[string]any) {
	t.Helper()
	path := filepath.Join(root, legacyLandingJournal)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySnapshotPreservesExactOwnedResources(t *testing.T) {
	root, _ := legacyFixture(t)
	snapshot, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != "node-example" || snapshot.Revision != 7 || len(snapshot.Files) != len(legacyLandingFiles) {
		t.Fatal("identity or resources lost")
	}
	for name, file := range snapshot.Files {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(raw, file.Contents) || file.Mode != 0600 {
			t.Fatal("snapshot changed owned file", err)
		}
	}
	before, err := os.ReadFile(filepath.Join(root, legacyLandingJournal))
	if err != nil || !bytes.Equal(before, snapshot.Journal) {
		t.Fatal("journal was rewritten", err)
	}
	backups := t.TempDir()
	first, err := backupLegacyLanding(backups, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := backupLegacyLanding(backups, snapshot)
	if err != nil || first == second {
		t.Fatal("backup replaced previous checkpoint", err)
	}
	for _, path := range []string{first, second} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("backup is not private", err)
		}
		raw, err := os.ReadFile(path)
		var restored LegacyLandingSnapshot
		if err != nil || json.Unmarshal(raw, &restored) != nil || !bytes.Equal(restored.Journal, snapshot.Journal) || !bytes.Equal(restored.Files[legacyLandingFiles[0]].Contents, snapshot.Files[legacyLandingFiles[0]].Contents) {
			t.Fatal("backup cannot preserve exact recovery contents", err)
		}
	}
}

func TestLegacySnapshotRejectsUnknownOrIncompleteOwnership(t *testing.T) {
	for _, scenario := range []string{"identity", "removed", "pending", "previous-policy", "missing", "changed", "symlink", "writable", "unknown-file"} {
		t.Run(scenario, func(t *testing.T) {
			root, metadata := legacyFixture(t)
			path := filepath.Join(root, legacyLandingFiles[0])
			switch scenario {
			case "identity":
				metadata["nodeId"] = "another-node"
			case "removed":
				metadata["removed"] = true
			case "pending":
				metadata["pendingFiles"] = map[string]string{"x": "y"}
			case "previous-policy":
				metadata["previousPolicy"] = map[string]any{"old": true}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "changed":
				if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, legacyLandingFiles[1]), path); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "unknown-file":
				metadata["files"].(map[string]string)["/etc/unrelated"] = "digest"
			}
			writeLegacyJournal(t, root, metadata)
			if _, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid())); err == nil {
				t.Fatal("unsafe legacy state accepted")
			}
		})
	}
}
