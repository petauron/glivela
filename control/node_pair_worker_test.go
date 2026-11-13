package control

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPairingPreflightDoesNotRecoverOrClaimLostStartupAcceptance(t *testing.T) {
	r, d := nativeFixture(t)
	if err := r.Apply(context.Background(), artifact(1)); err != nil {
		t.Fatal(err)
	}
	journal, _ := os.ReadFile(filepath.Join(r.Directory, "runtime.json"))
	config, _ := os.ReadFile(filepath.Join(r.Directory, "config.json"))
	starts, stops := d.starts, d.stops
	d.onHealth = func() { t.Fatal("offline state check invented live startup acceptance") }
	if _, err := r.pairingCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.CheckPairingSource(context.Background()) == nil {
		t.Fatal("generic fixture accepted as an installed native worker")
	}
	after, _ := os.ReadFile(filepath.Join(r.Directory, "runtime.json"))
	afterConfig, _ := os.ReadFile(filepath.Join(r.Directory, "config.json"))
	if !bytes.Equal(journal, after) || !bytes.Equal(config, afterConfig) || d.starts != starts || d.stops != stops {
		t.Fatal("pairing rewrote or restarted the source")
	}
	path := filepath.Join(r.Directory, "transport-prepared.json")
	if err := os.WriteFile(path, []byte("retained pending maintenance"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.pairingCurrent(context.Background()); err == nil {
		t.Fatal("pending maintenance accepted")
	}
}

func TestPairingDirectoriesRequireExactInstalledDeclarations(t *testing.T) {
	unit := "[Service]\nStateDirectory=app-node\nStateDirectory=app-pair\nStateDirectory=app-companion\n"
	paths := []string{"/var/lib/app-node", "/var/lib/app-pair", "/var/lib/app-companion"}
	if err := pairingDeclaredDirectories(unit, paths); err != nil {
		t.Fatal(err)
	}
	if err := pairingDeclaredDirectories(unit, []string{"/var/lib/another-application"}); err == nil {
		t.Fatal("foreign private directory accepted")
	}
	if err := pairingDeclaredDirectories(unit, []string{"/var/lib/app-node/../app-pair"}); err == nil {
		t.Fatal("unclean alias accepted")
	}
	if err := pairingDeclaredDirectories(unit+"StateDirectory=../foreign\n", paths); err == nil {
		t.Fatal("escaping declaration accepted")
	}
}

func TestPairingWorkerUsesExactCredentialSource(t *testing.T) {
	directory := "/var/lib/example-companion"
	plain := "LoadCredential=configuration.json:" + directory + "/config.json\n"
	quoted := "LoadCredential=configuration.json:\"" + directory + "/config.json\"\n"
	if err := pairingWorkerCredential(plain, directory); err != nil {
		t.Fatal(err)
	}
	if err := pairingWorkerCredential(quoted, directory); err != nil {
		t.Fatal(err)
	}
	if pairingWorkerCredential(plain, "/var/lib/another-application") == nil {
		t.Fatal("foreign state accepted")
	}
	if pairingWorkerCredential(plain+quoted, directory) == nil {
		t.Fatal("duplicate sources accepted")
	}
}
