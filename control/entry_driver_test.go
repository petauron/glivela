package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type entryDockerFixture struct {
	state                    entryContainerState
	starts, stops, mutations int
	failStart                bool
}

// No Docker daemon/image/container is used. Files/journal are real; the fixed
// Docker command boundary and process acceptance are simulated. Official-core,
// namespace policy and real installed Docker acceptance are separate gates.
func entryDriverFixture(t *testing.T) (*NativeRuntime, *EntryDriver, *entryDockerFixture, Desired) {
	t.Helper()
	c, desired, state := entryContainerFixture(t, os.Geteuid() == 0)
	canonical := func(path string) string {
		p, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c.ConfigurationDirectory = canonical(c.ConfigurationDirectory)
	state.Mounts[0].Source = c.ConfigurationDirectory
	if c.GID == 0 {
		c.UID = uint32(os.Geteuid())
		state.Config.User = strconv.Itoa(os.Geteuid())
	}
	d := &EntryDriver{Container: c, Directory: canonical(t.TempDir())}
	binary := "/usr/bin/true"
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	d.binary, d.binarySHA256 = binary, hex.EncodeToString(h[:])
	f := &entryDockerFixture{state: state}
	f.state.State.Status = "created"
	f.state.State.Running = false
	f.state.State.Pid = 0
	d.docker = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) == 5 && args[1] == "inspect" && args[2] == "--format" {
			if args[0] == "container" && args[3] == entryInspectTemplate && args[4] == c.ContainerID {
				return json.Marshal(f.state)
			}
			if args[0] == "network" && args[3] == entryBridgeTemplate && args[4] == c.NetworkID {
				return json.Marshal(map[string]any{"Id": c.NetworkID, "Name": c.NetworkName, "Driver": "bridge", "Scope": "local", "Internal": false, "Ingress": false, "Options": map[string]string{"com.docker.network.bridge.name": c.Bridge}})
			}
		}
		if len(args) == 3 && args[0] == "container" && args[1] == "start" && args[2] == c.ContainerID {
			f.starts++
			f.mutations++
			if f.failStart {
				f.failStart = false
				return nil, errors.New("anonymous start failure")
			}
			f.state.State.Status = "running"
			f.state.State.Running = true
			f.state.State.Pid = 12345
			f.state.State.StartedAt = time.Now().Add(-time.Millisecond).UTC().Format(time.RFC3339Nano)
			return nil, nil
		}
		if len(args) == 5 && args[0] == "container" && args[1] == "stop" && args[2] == "--time" && args[3] == "3" && args[4] == c.ContainerID {
			f.stops++
			f.mutations++
			f.state.State.Status = "exited"
			f.state.State.Running = false
			f.state.State.Pid = 0
			return nil, nil
		}
		t.Fatal("unexpected Docker action/target")
		return nil, errors.New("unexpected fixture action")
	}
	d.process = func(c EntryContainer, _ entryContainerState, desired Desired) error {
		return verifyEntryConfigFile(filepath.Join(c.ConfigurationDirectory, "config.json"), desired.Config)
	}
	r := &NativeRuntime{Directory: d.Directory, Driver: d}
	return r, d, f, desired
}

func TestEntryDriverConfigurationUpdateAndFailureRestore(t *testing.T) {
	r, d, worker, first := entryDriverFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, first); err != nil {
		t.Fatal("initial owned activation", err)
	}
	if worker.starts != 1 || worker.stops != 0 {
		t.Fatal("unexpected first lifecycle")
	}
	info, err := os.Stat(filepath.Join(d.Container.ConfigurationDirectory, "config.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("worker configuration is not private", err)
	}
	uid, err := entryFileUID(info)
	if err != nil || uid != d.Container.UID {
		t.Fatal("worker lost original file owner", err)
	}
	if _, err := os.Stat(filepath.Join(d.Container.ConfigurationDirectory, "runtime.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private recovery journal exposed through worker mount")
	}
	nextPlan := first.clone().Entry
	nextPlan.Revision++
	nextPlan.Credentials[0].Credential.User = "updated-entry-user"
	next, err := NewEntryDesired(*nextPlan, *first.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	worker.failStart = true
	if err := r.Apply(ctx, next); err == nil || !strings.Contains(err.Error(), "previous state restored") {
		t.Fatal("failed start was not recovered", err)
	}
	actual, err := r.Inspect(ctx)
	if err != nil || actual.Revision != first.Revision || !actual.RuntimeReady {
		t.Fatal("recovery did not restore checked first revision", err)
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Container.ConfigurationDirectory, "config.json"), first.Config); err != nil {
		t.Fatal("worker bytes were not restored", err)
	}
	if err := r.Apply(ctx, next); err != nil {
		t.Fatal("later valid update failed", err)
	}
	actual, err = r.Inspect(ctx)
	if err != nil || actual.Revision != next.Revision || !actual.RuntimeReady {
		t.Fatal("updated state not independently observed", err)
	}
	// A pure revision/program change with identical core configuration must
	// re-confirm state without resetting the shared worker's connections.
	beforeResume := worker.mutations
	unchangedPlan := next.clone().Entry
	unchangedPlan.Revision++
	unchanged, err := NewEntryDesired(*unchangedPlan, *next.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(ctx, unchanged); err != nil || worker.mutations != beforeResume {
		t.Fatal("unchanged core was needlessly restarted", err)
	}
	before := worker.mutations
	worker.state.Image = "sha256:" + strings.Repeat("e", 64)
	actual, err = r.Inspect(ctx)
	if err != nil || actual.RuntimeReady || worker.mutations != before {
		t.Fatal("health inspection repaired/restarted a replaced container", err)
	}
	if err := d.Close(ctx); err != nil || worker.mutations != before {
		t.Fatal("node shutdown stopped native entry", err)
	}
}

func TestEntryDriverRejectsUnownedConfigurationBeforeMutation(t *testing.T) {
	r, d, worker, desired := entryDriverFixture(t)
	path := filepath.Join(d.Container.ConfigurationDirectory, "config.json")
	unknown := []byte("anonymous unjournaled configuration")
	if err := os.WriteFile(path, unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if r.Apply(context.Background(), desired) == nil {
		t.Fatal("unowned working data accepted")
	}
	if worker.mutations != 0 {
		t.Fatal("unknown working service was stopped during first-install recovery")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != string(unknown) {
		t.Fatal("unknown data overwritten", err)
	}
	if _, err := os.Stat(filepath.Join(d.Directory, "runtime.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mutation intent saved before ownership accepted")
	}
}

func TestEntryDriverRejectsForeignRoleAndUnsafeMountDirectory(t *testing.T) {
	_, d, worker, desired := entryDriverFixture(t)
	ctx := context.Background()
	for _, err := range []error{d.Validate(ctx, artifact(1), "/unused"), d.Activate(ctx, artifact(1), nil), d.Activate(ctx, desired, ptrDesired(artifact(1))), d.Stop(ctx, artifact(1)), d.Healthy(ctx, artifact(1))} {
		if err == nil {
			t.Fatal("foreign landing role reached entry operations")
		}
	}
	if worker.mutations != 0 {
		t.Fatal("foreign role mutated container")
	}
	stable := d.Binding()
	d.Container.ContainerID = strings.Repeat("f", 64)
	d.Container.ImageID = "sha256:" + strings.Repeat("f", 64)
	if d.Binding() != stable {
		t.Fatal("versioned container identity redefined stable application identity")
	}
	d.Container.ConfigurationDirectory = d.Directory
	if d.Binding() != "" || d.checkDirectories() == nil {
		t.Fatal("worker allowed to read node journal directory")
	}
}

func ptrDesired(d Desired) *Desired { return &d }

func TestEntryDriverInterruptedIntentRestoresOriginalWorkerBytes(t *testing.T) {
	r, d, worker, first := entryDriverFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	plan := first.clone().Entry
	plan.Revision++
	plan.Credentials[0].Credential.User = "interrupted-candidate"
	next, err := NewEntryDesired(*plan, *first.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.save(runtimeJournal{Version: 1, Binding: d.Binding(), Phase: "pending", Current: &first, Candidate: &next}); err != nil {
		t.Fatal(err)
	}
	if err := replacePrivate(r.Directory, "config.json", next.Config); err != nil {
		t.Fatal(err)
	}
	if err := d.writeWorkerConfig(next.Config); err != nil {
		t.Fatal(err)
	}
	restarted := &NativeRuntime{Directory: r.Directory, Driver: d}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal("interrupted entry switch not recovered", err)
	}
	actual, err := restarted.Inspect(ctx)
	if err != nil || actual.Revision != first.Revision || !actual.RuntimeReady || worker.starts != 2 {
		t.Fatal("recovery did not accept original checked runtime", err)
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Container.ConfigurationDirectory, "config.json"), first.Config); err != nil {
		t.Fatal(err)
	}
}

func TestEntryDriverFailedRecoveryStaysPendingUntilActualRepair(t *testing.T) {
	r, d, worker, first := entryDriverFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	plan := first.clone().Entry
	plan.Revision++
	plan.Credentials[0].Credential.User = "candidate-after-storage-fault"
	next, err := NewEntryDesired(*plan, *first.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	original := d.docker
	moved := false
	preserved := d.Container.ConfigurationDirectory + "-preserved"
	d.docker = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := original(ctx, args...)
		if err == nil && !moved && len(args) > 1 && args[1] == "stop" {
			// Preserve all bytes, simulating unavailable worker storage only
			// after the old process has stopped. Never delete the fixture data.
			if err := os.Rename(d.Container.ConfigurationDirectory, preserved); err != nil {
				t.Fatal(err)
			}
			moved = true
		}
		return raw, err
	}
	if err := r.Apply(ctx, next); err == nil || !strings.Contains(err.Error(), "recovery required") {
		t.Fatal("failed recovery was reported as success", err)
	}
	if _, err := r.Inspect(ctx); err == nil || worker.state.State.Running {
		t.Fatal("pending failed recovery reported ready")
	}
	if err := verifyEntryConfigFile(filepath.Join(preserved, "config.json"), first.Config); err != nil {
		t.Fatal("preserved data changed", err)
	}
	if err := os.Rename(preserved, d.Container.ConfigurationDirectory); err != nil {
		t.Fatal(err)
	}
	if err := r.Recover(ctx); err != nil {
		t.Fatal("repair did not allow original-state recovery", err)
	}
	actual, err := r.Inspect(ctx)
	if err != nil || !actual.RuntimeReady || actual.Revision != first.Revision {
		t.Fatal("repaired runtime did not match original state", err)
	}
}
