package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type driverFixture struct {
	validErr      error
	starts, stops int
	failHealth    int
	binding       string
	active        Desired
	prior         *Desired
}

func (f *driverFixture) Binding() string { return "fixture:" + f.binding }

func (f *driverFixture) Validate(context.Context, string) error { return f.validErr }
func (f *driverFixture) Activate(_ context.Context, desired Desired, prior *Desired) error {
	f.starts++
	f.active = desired.clone()
	f.prior = prior
	return nil
}
func (f *driverFixture) Stop(context.Context, Desired) error { f.stops++; return nil }
func (f *driverFixture) Healthy(context.Context, Desired) error {
	if f.failHealth > 0 {
		f.failHealth--
		return errors.New("unhealthy")
	}
	return nil
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
