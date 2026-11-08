package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewerAuthenticatedAssignmentSupersedesFailedPending(t *testing.T) {
	ctx := context.Background()
	r, d := nativeFixture(t)
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	d.activationError = func(v Desired) error {
		if v.Revision <= 2 {
			return errors.New("old bind unavailable")
		}
		return nil
	}
	if r.Apply(ctx, artifact(2)) == nil {
		t.Fatal("unavailable bind accepted")
	}
	state, err := r.journal()
	if err != nil || state.Phase != "pending" || state.Candidate.Revision != 2 {
		t.Fatal("pending evidence missing", err)
	}
	for _, v := range []Desired{artifact(1), artifact(2)} {
		if v.Revision == 2 {
			v.ConfigSHA256 = "invalid"
		}
		if r.ResumeAssigned(ctx, v) == nil {
			t.Fatal("rollback or reused revision accepted")
		}
	}
	d.validErr = errors.New("new candidate invalid")
	if r.ResumeAssigned(ctx, artifact(3)) == nil {
		t.Fatal("unvalidated replacement accepted")
	}
	state, _ = r.journal()
	if state.Candidate.Revision != 2 {
		t.Fatal("validation failure replaced pending intent")
	}
	d.validErr = nil
	pending, err := os.ReadFile(filepath.Join(r.Directory, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	intent := filepath.Join(r.Directory, "commit-pending.json")
	if err := os.WriteFile(intent, pending, 0600); err != nil {
		t.Fatal(err)
	}
	if r.ResumeAssigned(ctx, artifact(3)) == nil {
		t.Fatal("unresolved commit was superseded")
	}
	if err := os.Remove(intent); err != nil {
		t.Fatal(err)
	}
	if err := r.ResumeAssigned(ctx, artifact(3)); err != nil {
		t.Fatal(err)
	}
	actual, err := r.Inspect(ctx)
	if err != nil || actual.Revision != 3 || !actual.RuntimeReady {
		t.Fatal("new assignment not committed", err)
	}
	old := artifact(2)
	path := filepath.Join(r.Directory, "backup-2-"+old.ConfigSHA256+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("superseded candidate recovery missing", err)
	}
}
