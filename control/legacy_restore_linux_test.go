package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryResourceBindingDoesNotDependOnCurrentAgentBinary(t *testing.T) {
	root, _ := legacyFixture(t)
	saved, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(root, "/usr/local/bin/vastora")
	if err := os.Chmod(program, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("\x7fELFnew installed version; never executed"), 0700); err != nil {
		t.Fatal(err)
	}
	current, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if saved.RecoveryProgram.SHA256 == current.RecoveryProgram.SHA256 {
		t.Fatal("fixture binary unchanged")
	}
	if !sameLegacyResources(saved, current) {
		t.Fatal("unchanged legacy resources rejected after installer update")
	}
	current.Journal = append(current.Journal, ' ')
	if sameLegacyResources(saved, current) {
		t.Fatal("changed journal accepted")
	}
}
