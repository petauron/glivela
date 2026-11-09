package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPairingRetainsEitherExistingRole(t *testing.T) {
	for _, role := range []string{"entry", "landing"} {
		t.Run(role, func(t *testing.T) {
			pair := pairedBootstrap()
			before := *pair.EntryNode
			if role == "landing" {
				before = *pair.LandingNode
			}
			saved := before
			other, err := preservedPairRole(before, pair)
			if err != nil || other.Xray.Role == role || !reflect.DeepEqual(saved, before) {
				t.Fatal("existing role or independent companion changed", err)
			}
			for _, fault := range []string{"identity", "worker", "journal", "controller", "installation"} {
				t.Run(fault, func(t *testing.T) {
					bad := before
					switch fault {
					case "identity":
						bad.Certificate = "/private/replaced.crt"
					case "worker":
						bad.Xray.Service = "foreign-xray"
					case "journal":
						bad.Directory = "/private/replaced-state"
					case "controller":
						bad.Controller = "https://controller.example.invalid"
					case "installation":
						bad.Installation = "/private/foreign.json"
					}
					if _, err := preservedPairRole(bad, pair); err == nil {
						t.Fatal("unsafe role replacement accepted")
					}
				})
			}
		})
	}
}

func TestPairBackupIsStableAndNeverOverwritesRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single-role-bootstrap.json")
	original := []byte(`{"mode":"node","identity":"original"}`)
	if err := savePairBackup(path, original); err != nil {
		t.Fatal(err)
	}
	if err := savePairBackup(path, original); err != nil {
		t.Fatal("same change must reuse recovery", err)
	}
	if err := savePairBackup(path, []byte("replacement")); err == nil {
		t.Fatal("recovery overwritten")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("original recovery lost", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("recovery not private")
	}
	target := filepath.Join(dir, "foreign")
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := savePairBackup(link, original); err == nil {
		t.Fatal("symlink recovery accepted")
	}
}
