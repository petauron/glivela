package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	glivela "github.com/petauron/glivela"
)

func recoveryContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// Driver is implemented by Glivela's native Xray adapter. It is deliberately
// not a remote execution protocol or a Vastora integration interface.
type Driver interface {
	Binding() string
	Validate(context.Context, string) error
	Activate(context.Context, Desired, *Desired) error
	Stop(context.Context, Desired) error
	Healthy(context.Context, Desired) error
}

type runtimeJournal struct {
	Version   int      `json:"version"`
	Binding   string   `json:"binding"`
	Phase     string   `json:"phase"`
	Current   *Desired `json:"current,omitempty"`
	Candidate *Desired `json:"candidate,omitempty"`
}

// NativeRuntime owns one private directory and one dedicated Xray service.
// Existing applications must be explicitly handed over before use; an
// unjournaled config file is never silently adopted or overwritten.
type NativeRuntime struct {
	mu        sync.Mutex
	Directory string
	Driver    Driver
}

func (r *NativeRuntime) journal() (runtimeJournal, error) {
	var state runtimeJournal
	if r.Driver == nil || !filepath.IsAbs(r.Directory) {
		return state, errors.New("control: runtime not configured")
	}
	for parent := r.Directory; parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return state, errors.New("control: unsafe runtime directory")
		}
		if parent == r.Directory && info.Mode().Perm()&0077 != 0 {
			return state, errors.New("control: runtime directory must be private")
		}
	}
	path := filepath.Join(r.Directory, "runtime.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, configErr := os.Lstat(filepath.Join(r.Directory, "config.json")); !errors.Is(configErr, os.ErrNotExist) {
			return state, errors.New("control: unowned runtime config")
		}
		return state, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 3*maxMessage {
		return state, errors.New("control: invalid runtime journal")
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &state) != nil || state.Version != 1 {
		return state, errors.New("control: unreadable runtime journal")
	}
	if state.Binding == "" || state.Binding != r.Driver.Binding() {
		return state, errors.New("control: local runtime identity changed; explicit handover required")
	}
	if state.Current != nil && state.Current.Validate() != nil || state.Candidate != nil && state.Candidate.Validate() != nil {
		return state, errors.New("control: damaged runtime artifacts")
	}
	if state.Phase != "ready" && state.Phase != "pending" || state.Phase == "ready" && state.Candidate != nil || state.Phase == "pending" && state.Candidate == nil {
		return state, errors.New("control: invalid runtime phase")
	}
	return state, nil
}

func (r *NativeRuntime) save(state runtimeJournal) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return replacePrivate(r.Directory, "runtime.json", raw)
}

func replacePrivate(directory, name string, contents []byte) error {
	path := filepath.Join(directory, name)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("control: unsafe managed file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(directory, ".glivela-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (r *NativeRuntime) Apply(ctx context.Context, desired Desired) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if desired.Validate() != nil {
		return errors.New("control: invalid runtime artifact")
	}
	state, err := r.journal()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		state = runtimeJournal{Version: 1, Phase: "ready", Binding: r.Driver.Binding()}
		if state.Binding == "" {
			return errors.New("control: runtime binding required")
		}
	}
	if state.Phase != "ready" {
		return errors.New("control: recovery required")
	}
	if state.Current != nil && desired.Revision <= state.Current.Revision {
		return errors.New("control: runtime revision must advance")
	}
	if state.Current != nil {
		if err := r.verifyConfig(*state.Current); err != nil {
			return err
		}
		if err := r.backup(*state.Current); err != nil {
			return err
		}
	}
	// Validate before changing intent or stopping a working service.
	if err = replacePrivate(r.Directory, "candidate.json", desired.Config); err != nil {
		return err
	}
	if err = r.Driver.Validate(ctx, filepath.Join(r.Directory, "candidate.json")); err != nil {
		return errors.New("control: Xray configuration rejected")
	}
	state.Phase = "pending"
	state.Candidate = &desired
	if err = r.save(state); err != nil {
		return err
	}
	if err = replacePrivate(r.Directory, "config.json", desired.Config); err == nil {
		err = r.Driver.Activate(ctx, desired, state.Current)
	}
	if err == nil {
		err = r.Driver.Healthy(ctx, desired)
	}
	if err != nil {
		// A cancelled upgrade must still get a bounded opportunity to restore
		// its previous service, not reuse the cancelled operation context.
		recovery, cancel := recoveryContext()
		defer cancel()
		if restoreErr := r.restore(recovery, state); restoreErr != nil {
			return errors.New("control: activation failed; recovery required")
		}
		return errors.New("control: activation failed; previous state restored")
	}
	committed := state
	committed.Current = &desired
	committed.Candidate = nil
	committed.Phase = "ready"
	if err := r.save(committed); err != nil {
		// Activation is not committed until its journal is durable. Recover
		// from the original pending state, including when rename succeeded but
		// directory sync failed. Never report the candidate as installed.
		recovery, cancel := recoveryContext()
		defer cancel()
		if restoreErr := r.restore(recovery, state); restoreErr != nil {
			return errors.New("control: commit failed; recovery required")
		}
		return errors.New("control: commit failed; previous state restored")
	}
	return nil
}

func (r *NativeRuntime) restore(ctx context.Context, state runtimeJournal) error {
	if state.Candidate == nil {
		return errors.New("control: missing recovery candidate")
	}
	if err := r.verifyConfig(*state.Candidate); err != nil {
		if state.Current != nil {
			if r.verifyConfig(*state.Current) != nil {
				return errors.New("control: recovery config is unowned")
			}
		} else if _, statErr := os.Lstat(filepath.Join(r.Directory, "config.json")); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("control: recovery config is unowned")
		}
	}
	if state.Current == nil {
		if err := r.Driver.Stop(ctx, *state.Candidate); err != nil {
			return err
		}
	} else {
		if err := replacePrivate(r.Directory, "config.json", state.Current.Config); err != nil {
			return err
		}
		if err := r.Driver.Validate(ctx, filepath.Join(r.Directory, "config.json")); err != nil {
			return err
		}
		if err := r.Driver.Activate(ctx, *state.Current, state.Candidate); err != nil {
			return err
		}
		if err := r.Driver.Healthy(ctx, *state.Current); err != nil {
			return err
		}
	}
	state.Phase = "ready"
	state.Candidate = nil
	return r.save(state)
}

func (r *NativeRuntime) backup(a Desired) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("backup-%d-%s.json", a.Revision, a.ConfigSHA256)
	path := filepath.Join(r.Directory, name)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxMessage {
			return errors.New("control: unsafe recovery backup")
		}
		existing, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(existing, raw) {
			return errors.New("control: recovery backup changed")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return replacePrivate(r.Directory, name, raw)
}

// Recover runs at node startup before polling. It restores the committed
// configuration after an interrupted switch; it never upgrades from a partial
// journal or marks an unchecked candidate successful.
func (r *NativeRuntime) Recover(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.journal()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Phase == "pending" {
		return r.restore(ctx, state)
	}
	return nil
}

func (r *NativeRuntime) Inspect(ctx context.Context) (glivela.AppliedReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.journal()
	if err != nil {
		return glivela.AppliedReceipt{}, err
	}
	if state.Phase != "ready" {
		return glivela.AppliedReceipt{}, errors.New("control: pending runtime recovery")
	}
	if state.Current == nil {
		return glivela.AppliedReceipt{}, os.ErrNotExist
	}
	a := *state.Current
	if err := r.verifyConfig(a); err != nil {
		return glivela.AppliedReceipt{}, err
	}
	return glivela.AppliedReceipt{Revision: a.Revision, ConfigSHA256: a.ConfigSHA256, RuntimeReady: r.Driver.Healthy(ctx, a) == nil}, nil
}

func (r *NativeRuntime) verifyConfig(a Desired) error {
	info, err := os.Lstat(filepath.Join(r.Directory, "config.json"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxMessage {
		return errors.New("control: cannot verify active config")
	}
	raw, err := os.ReadFile(filepath.Join(r.Directory, "config.json"))
	if err != nil {
		return err
	}
	a.Config = raw
	if a.Validate() != nil {
		return errors.New("control: active config differs from committed state")
	}
	return nil
}
