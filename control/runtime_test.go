package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type driverFixture struct {
	validErr        error
	starts, stops   int
	failHealth      int
	binding         string
	active          Desired
	running         bool
	prior           *Desired
	onHealth        func()
	onActivate      func(Desired)
	activationError func(Desired) error
}

func (f *driverFixture) Binding() string { return "fixture:" + f.binding }

func (f *driverFixture) EntryHealth(Desired) *EntryHealthReport { return nil }

func (f *driverFixture) Validate(context.Context, Desired, string) error { return f.validErr }
func (f *driverFixture) Activate(_ context.Context, desired Desired, prior *Desired) error {
	if f.activationError != nil {
		if err := f.activationError(desired); err != nil {
			return err
		}
	}
	f.starts++
	f.active = desired.clone()
	f.running = true
	f.prior = prior
	if f.onActivate != nil {
		f.onActivate(desired)
	}
	return nil
}

func TestReadyRenameSyncFailureAndFailedRecoveryRemainPending(t *testing.T) {
	r, d := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	r.writeJournal = func(directory, name string, raw []byte) error {
		if err := replacePrivate(directory, name, raw); err != nil {
			return err
		}
		var state runtimeJournal
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
		if state.Phase == "ready" && state.Current != nil && state.Current.Revision == 2 {
			return errors.New("injected directory fsync failure after ready rename")
		}
		return nil
	}
	d.activationError = func(desired Desired) error {
		if desired.Revision == 1 {
			return errors.New("injected restore failure")
		}
		return nil
	}
	if err := r.Apply(ctx, artifact(2)); err == nil || !strings.Contains(err.Error(), "recovery required") {
		t.Fatal("compound failure accepted", err)
	}
	if d.active.Revision != 2 {
		t.Fatal("fixture did not retain running candidate")
	}
	// Simulate a process restart: no in-memory fault flag can protect us now.
	restarted := &NativeRuntime{Directory: r.Directory, Driver: d}
	if _, err := restarted.Inspect(ctx); err == nil {
		t.Fatal("ready bytes hid unfinished recovery")
	}
	if err := restarted.Recover(ctx); err == nil {
		t.Fatal("restart skipped failed restoration")
	}
	d.activationError = nil
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := restarted.Inspect(ctx)
	if err != nil || actual.Revision != 1 || !actual.RuntimeReady {
		t.Fatal("previous runtime not recovered", err)
	}
}

func TestPendingUnlinkSyncFailureDoesNotExposeCandidateSuccess(t *testing.T) {
	r, d := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	r.syncCommitDirectory = func(*os.File) error { return errors.New("injected fsync failure after unlink") }
	d.activationError = func(desired Desired) error {
		if desired.Revision == 1 {
			return errors.New("injected recovery unavailable")
		}
		return nil
	}
	if err := r.Apply(ctx, artifact(2)); err == nil || !strings.Contains(err.Error(), "recovery required") {
		t.Fatal("uncertain cleanup accepted", err)
	}
	if _, err := r.Inspect(ctx); err == nil {
		t.Fatal("candidate reported ready after failed unlink sync")
	}
	restarted := &NativeRuntime{Directory: r.Directory, Driver: d}
	if _, err := restarted.Inspect(ctx); err == nil {
		t.Fatal("restart lost unfinished recovery")
	}
	d.activationError = nil
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := restarted.Inspect(ctx)
	if err != nil || actual.Revision != 1 {
		t.Fatal("previous revision not recovered", err)
	}
}
func (f *driverFixture) Stop(context.Context, Desired) error {
	f.stops++
	f.running = false
	return nil
}
func (f *driverFixture) Healthy(context.Context, Desired) error {
	if !f.running {
		return errors.New("worker is stopped")
	}
	if f.onHealth != nil {
		f.onHealth()
	}
	if f.failHealth > 0 {
		f.failHealth--
		return errors.New("unhealthy")
	}
	return nil
}

func TestNativeCommitFailureRestoresPreviousRuntime(t *testing.T) {
	for _, storageRecovers := range []bool{true, false} {
		t.Run(fmt.Sprint(storageRecovers), func(t *testing.T) {
			r, d := nativeFixture(t)
			ctx := context.Background()
			if err := r.Apply(ctx, artifact(1)); err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(r.Directory, "runtime.json")
			d.onHealth = func() {
				d.onHealth = nil
				// Make the final commit fail after successful candidate health.
				if err := os.Chmod(journal, 0644); err != nil {
					t.Fatal(err)
				}
			}
			d.onActivate = func(desired Desired) {
				if storageRecovers && desired.Revision == 1 {
					if err := os.Chmod(journal, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := r.Apply(ctx, artifact(2))
			if err == nil || d.active.Revision != 1 || d.starts != 3 {
				t.Fatal("commit failure left candidate running", err)
			}
			actual, inspectErr := r.Inspect(ctx)
			if storageRecovers {
				if inspectErr != nil || actual.Revision != 1 || !actual.RuntimeReady {
					t.Fatal("old state not durably recovered", inspectErr)
				}
			} else if inspectErr == nil || !strings.Contains(err.Error(), "recovery required") {
				t.Fatal("uncommitted recovery was reported successful", err, inspectErr)
			}
		})
	}
}
func nativeFixture(t *testing.T) (*NativeRuntime, *driverFixture) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := &driverFixture{}
	return &NativeRuntime{Directory: dir, Driver: d}, d
}
func TestNativeApplyAndRollback(t *testing.T) {
	r, d := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	d.failHealth = 1
	if r.Apply(ctx, artifact(2)) == nil {
		t.Fatal("failed candidate accepted")
	}
	actual, err := r.Inspect(ctx)
	if err != nil || actual.Revision != 1 || !actual.RuntimeReady {
		t.Fatalf("old state not restored: %+v %v", actual, err)
	}
	if d.starts != 3 {
		t.Fatal("expected activation and restoration")
	}
	d.validErr = errors.New("bad config")
	if r.Apply(ctx, artifact(2)) == nil || d.starts != 3 {
		t.Fatal("invalid config disturbed runtime")
	}
}
func TestNativeRestartRecovery(t *testing.T) {
	r, _ := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	state, err := r.journal()
	if err != nil {
		t.Fatal(err)
	}
	candidate := artifact(2)
	state.Candidate = &candidate
	state.Phase = "pending"
	if err = r.save(state); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Inspect(ctx); err == nil {
		t.Fatal("pending accepted")
	}
	if err = r.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := r.Inspect(ctx)
	if err != nil || actual.Revision != 1 {
		t.Fatal("wrong recovered revision")
	}
}
func TestNativeDoesNotAdoptUnknownConfig(t *testing.T) {
	r, d := nativeFixture(t)
	if err := os.WriteFile(filepath.Join(r.Directory, "config.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if r.Apply(context.Background(), artifact(1)) == nil || d.starts != 0 {
		t.Fatal("unknown runtime overwritten")
	}
}
func TestNativeTamperingFailsClosed(t *testing.T) {
	r, _ := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Directory, "config.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Inspect(ctx); err == nil {
		t.Fatal("tampered runtime accepted")
	}
}
func TestNativeInitialFailureStopsCandidate(t *testing.T) {
	r, d := nativeFixture(t)
	d.failHealth = 1
	if r.Apply(context.Background(), artifact(1)) == nil || d.stops != 1 {
		t.Fatal("initial failure not stopped")
	}
	if _, err := r.Inspect(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("initial failure became ready")
	}
}

func TestCommittedWorkerRestoredAtStartupWithoutNewRevision(t *testing.T) {
	r, d := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(r.Directory, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	d.running = false // A reboot stops the manual service and loses nft tables.
	restarted := &NativeRuntime{Directory: r.Directory, Driver: d}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := restarted.Inspect(ctx)
	if err != nil || actual.Revision != 1 || !actual.RuntimeReady || d.starts != 2 {
		t.Fatal("committed runtime not restored", err)
	}
	if err := (NodeRunner{Client: &fakeClient{desired: artifact(1)}, Runtime: restarted}).Step(ctx); err != nil {
		t.Fatal(err)
	}
	if d.starts != 2 {
		t.Fatal("unchanged controller revision reapplied")
	}
	after, err := os.ReadFile(filepath.Join(r.Directory, "runtime.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("startup reinitialized committed data")
	}
	// A later health loss is reported, not handled by repeated restarts.
	d.running = false
	if (NodeRunner{Client: &fakeClient{desired: artifact(1)}, Runtime: restarted}).Step(ctx) == nil || d.starts != 2 {
		t.Fatal("health loop restarted the worker")
	}
}

func TestStartupRefusesTamperedCommittedConfiguration(t *testing.T) {
	r, d := nativeFixture(t)
	if err := r.Apply(context.Background(), artifact(1)); err != nil {
		t.Fatal(err)
	}
	d.running = false
	if err := os.WriteFile(filepath.Join(r.Directory, "config.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Recover(context.Background()); err == nil || d.starts != 1 {
		t.Fatal("tampered startup configuration activated")
	}
}

func TestStartupActivationFailureStopsWorkerWithoutChangingRevision(t *testing.T) {
	r, d := nativeFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, artifact(1)); err != nil {
		t.Fatal(err)
	}
	d.running = false
	d.activationError = func(Desired) error { return errors.New("startup activation failed") }
	if err := r.Recover(ctx); err == nil || d.stops != 1 || d.running {
		t.Fatal("failed startup not stopped", err)
	}
	state, err := r.journal()
	if err != nil || state.Current.Revision != 1 {
		t.Fatal("failed startup changed committed revision", err)
	}
}
