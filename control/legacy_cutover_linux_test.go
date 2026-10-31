package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyCutoverJournalPinsCandidateAndBlocksSilentRetry(t *testing.T) {
	r, driver := nativeFixture(t)
	candidate := artifact(1)
	state := legacyCutover{Version: 1, NodeID: "node-example", Checkpoint: "/private-recovery/checkpoint/snapshot.json", Binding: r.Driver.Binding(), Phase: "pending", Candidate: candidate}
	if err := saveLegacyCutover(r.Directory, state); err != nil {
		t.Fatal(err)
	}
	got, err := readLegacyCutover(r)
	if err != nil || got.Phase != "pending" || got.Candidate.ConfigSHA256 != candidate.ConfigSHA256 {
		t.Fatal("cutover checkpoint changed", err)
	}
	if err := checkLegacyCutoverApply(r, candidate); err != nil {
		t.Fatal(err)
	}
	if checkLegacyCutoverApply(r, artifact(2)) == nil {
		t.Fatal("unaccepted migration allowed another revision")
	}
	state.Phase = "awaiting-routes"
	if err := saveLegacyCutover(r.Directory, state); err != nil {
		t.Fatal(err)
	}
	if checkLegacyCutoverApply(r, artifact(2)) == nil {
		t.Fatal("local readiness bypassed route acceptance")
	}
	if r.Apply(context.Background(), artifact(2)) == nil || driver.starts != 0 {
		t.Fatal("native apply bypassed the migration gate")
	}
	state.Phase = "rolled-back"
	if err := saveLegacyCutover(r.Directory, state); err != nil {
		t.Fatal(err)
	}
	if checkLegacyCutoverApply(r, candidate) == nil {
		t.Fatal("rolled-back switch would silently retry")
	}
	if r.Apply(context.Background(), candidate) == nil || driver.starts != 0 {
		t.Fatal("rolled-back migration restarted a candidate")
	}
	state.Phase = "accepted"
	state.AcceptedSnapshot = "verified-snapshot"
	state.AcceptedAt = time.Now().UTC()
	if err := saveLegacyCutover(r.Directory, state); err != nil {
		t.Fatal(err)
	}
	got, err = readLegacyCutover(r)
	if err != nil || got.AcceptedSnapshot != state.AcceptedSnapshot || !got.AcceptedAt.Equal(state.AcceptedAt) {
		t.Fatal("accepted route evidence was not retained", err)
	}
}

func TestLegacyCutoverRejectsUnsafeCheckpoint(t *testing.T) {
	for _, scenario := range []string{"unknown phase", "missing acceptance", "wrong binding", "changed candidate", "public file", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			r, _ := nativeFixture(t)
			state := legacyCutover{Version: 1, NodeID: "node-example", Checkpoint: "/private-recovery/checkpoint/snapshot.json", Binding: r.Driver.Binding(), Phase: "pending", Candidate: artifact(1)}
			switch scenario {
			case "unknown phase":
				state.Phase = "success"
			case "missing acceptance":
				state.Phase = "accepted"
			case "wrong binding":
				state.Binding = "other"
			case "changed candidate":
				state.Candidate.ConfigSHA256 = strings.Repeat("0", 64)
			}
			if err := saveLegacyCutover(r.Directory, state); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.Directory, "legacy-cutover.json")
			if scenario == "public file" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink" {
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readLegacyCutover(r); err == nil {
				t.Fatal("invalid cutover checkpoint accepted")
			}
		})
	}
}

func TestLegacyProxyStopRequiresAllProcessesStopped(t *testing.T) {
	valid := "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n"
	if !legacyProxyStopped(valid) {
		t.Fatal("stopped proxy refused")
	}
	for _, raw := range []string{strings.Replace(valid, "MainPID=0", "MainPID=45", 1), strings.Replace(valid, "ControlPID=0", "ControlPID=46", 1), strings.Replace(valid, "SubState=dead", "SubState=running", 1), strings.Replace(valid, "ControlPID=0\n", "", 1), valid + "MainPID=0\n"} {
		if legacyProxyStopped(raw) {
			t.Fatal("unconfirmed stop accepted")
		}
	}
}
