package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyWriterFenceRequiresPersistentStoppedUnit(t *testing.T) {
	valid := "LoadState=masked\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nUnitFileState=masked\n"
	if !legacyWriterStopped(valid) {
		t.Fatal("stopped persistent fence refused")
	}
	for _, bad := range []string{
		strings.Replace(valid, "LoadState=masked", "LoadState=loaded", 1),
		strings.Replace(valid, "ActiveState=inactive", "ActiveState=active", 1),
		strings.Replace(valid, "MainPID=0", "MainPID=123", 1),
		strings.Replace(valid, "ControlPID=0", "ControlPID=123", 1),
		strings.Replace(valid, "UnitFileState=masked", "UnitFileState=masked-runtime", 1),
		strings.Replace(valid, "SubState=dead\n", "", 1),
		strings.Replace(valid, "SubState=dead", "Unknown=", 1),
		valid + "MainPID=0\n",
	} {
		if legacyWriterStopped(bad) {
			t.Fatal("incomplete writer fence accepted")
		}
	}
}

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
