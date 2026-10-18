package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

func TestOfflineAccountImport(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	plan, err := glivela.PlanImport(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{4}, 32)
	sealed, err := glivela.SealImportMaterial(glivela.ImportMaterial{Plan: plan}, key, "snapshot-empty")
	if err != nil {
		t.Fatal(err)
	}
	keyPath, input := filepath.Join(directory, "key"), filepath.Join(directory, "import.sealed")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageAccounts(input, "snapshot-empty", directory, keyPath, keyPath); err != nil {
		t.Fatal(err)
	}
	stored, id, err := control.ReadStagedAccounts(directory, key)
	if err != nil || id != "snapshot-empty" || len(stored.Plan.Accounts) != 0 {
		t.Fatal("empty authoritative inventory was not retained", err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if stageAccounts(input, "snapshot-empty", directory, keyPath, keyPath) == nil {
		t.Fatal("public key file accepted")
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "key-alias")
	if err := os.Symlink(keyPath, alias); err != nil {
		t.Fatal(err)
	}
	if stageAccounts(input, "snapshot-empty", directory, alias, keyPath) == nil {
		t.Fatal("symlink key accepted")
	}
}
