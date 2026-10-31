package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

// EntryRuntime is the node's local resource boundary. The caller holds the
// node-directory lease. Only a locally authorized template can create a new
// worker; a desired message alone never authorizes adoption or host resources.
type EntryRuntime struct {
	Template                                  EntryContainer
	Directory, Distribution, LegacyCheckpoint string
	AllowProvision                            bool
	runtime                                   *NativeRuntime
}

func (r *EntryRuntime) load(ctx context.Context) error {
	if r.runtime != nil {
		return nil
	}
	path := filepath.Join(r.Directory, "entry-install.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
		return errors.New("control: invalid local entry installation")
	}
	raw, err := os.ReadFile(path)
	var installed entryInstall
	if err != nil || decode(bytes.NewReader(raw), &installed) != nil || installed.Version != 1 || installed.Container.validate() != nil {
		return errors.New("control: entry installation cannot be read")
	}
	if installed.Retired {
		return errors.New("control: entry has been retired; activation refused")
	}
	expected, err := resolveEntryEnvironment(ctx, r.Template)
	if err != nil {
		return err
	}
	actual := installed.Container
	if expected.ContainerID != "" && (expected.ContainerID != actual.ContainerID || expected.ImageID != actual.ImageID) {
		return errors.New("control: entry bootstrap ownership changed")
	}
	expected.ContainerID, expected.ImageID = "", ""
	actual.ContainerID, actual.ImageID = "", ""
	if !reflect.DeepEqual(expected, actual) {
		return errors.New("control: entry installation differs from local scope")
	}
	driver, err := ResolveEntryDriver(installed.Container, r.Directory, r.Distribution)
	if err != nil {
		return err
	}
	r.runtime = &NativeRuntime{Directory: r.Directory, Driver: driver}
	return nil
}

func (r *EntryRuntime) Recover(ctx context.Context) error {
	if err := r.load(ctx); err != nil {
		return err
	}
	if r.runtime == nil {
		return nil
	}
	if err := r.checkHandover(); err != nil {
		return err
	}
	return r.runtime.Recover(ctx)
}

func (r *EntryRuntime) Inspect(ctx context.Context) (Observation, error) {
	if err := r.load(ctx); err != nil {
		return Observation{}, err
	}
	if r.runtime == nil {
		return Observation{}, os.ErrNotExist
	}
	if err := r.checkHandover(); err != nil {
		return Observation{}, err
	}
	return r.runtime.Inspect(ctx)
}

func (r *EntryRuntime) Apply(ctx context.Context, desired Desired) error {
	if err := r.load(ctx); err != nil {
		return err
	}
	if r.runtime == nil {
		if !r.AllowProvision || desired.Entry == nil || r.Template.ContainerID != "" || r.Template.ImageID != "" {
			return errors.New("control: local entry provisioning has not been authorized")
		}
		var err error
		if r.LegacyCheckpoint != "" {
			_, err = adoptLegacyEntry(ctx, r.LegacyCheckpoint, r.Template, r.Directory, r.Distribution, desired, true)
		} else {
			_, err = provisionEntryLocked(ctx, r.Template, r.Directory, r.Distribution, desired)
		}
		if err != nil {
			return err
		}
		if err := r.Recover(ctx); err != nil {
			return err
		}
	}
	if err := r.checkHandover(); err != nil {
		return err
	}
	return r.runtime.Apply(ctx, desired)
}

func (r *EntryRuntime) checkHandover() error {
	if r.LegacyCheckpoint == "" {
		return nil
	}
	phase, err := os.ReadFile(filepath.Join(filepath.Dir(r.LegacyCheckpoint), "switch.json"))
	if err != nil || string(phase) != "awaiting-routes" {
		return errors.New("control: entry handover recovery must finish before node activation")
	}
	return nil
}

func (r *EntryRuntime) Close(ctx context.Context) error {
	if r.runtime == nil {
		return nil
	}
	return r.runtime.Driver.(*EntryDriver).Close(ctx)
}

// Native installation owns the private state parent. Glivela creates only
// these two declared children, never changes an existing directory's owner,
// and never gives its worker access to the journal or controller credentials.
func PrepareEntryDirectories(template EntryContainer, directory string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Dir(template.ConfigurationDirectory) != filepath.Dir(directory) || entryPathsOverlap(template.ConfigurationDirectory, directory) {
		return errors.New("control: entry requires separate children of its private state directory")
	}
	proposed := template
	proposed.ContainerID = "0000000000000000000000000000000000000000000000000000000000000000"
	proposed.ImageID = "sha256:" + proposed.ContainerID
	if proposed.validate() != nil {
		return errors.New("control: invalid local entry scope")
	}
	for parent := filepath.Dir(directory); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("control: unsafe entry state ancestry")
		}
		owner, err := entryFileUID(info)
		if err != nil || owner != 0 {
			return errors.New("control: entry state ancestry has a foreign owner")
		}
	}
	for _, item := range []struct {
		path string
		uid  uint32
	}{{directory, 0}, {template.ConfigurationDirectory, template.UID}} {
		info, err := os.Lstat(item.path)
		if errors.Is(err, os.ErrNotExist) {
			parent, parentErr := os.Lstat(filepath.Dir(item.path))
			if parentErr != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
				return errors.New("control: private installed entry state parent required")
			}
			owner, ownerErr := entryFileUID(parent)
			if ownerErr != nil || owner != 0 {
				return errors.New("control: entry state parent must belong to the node")
			}
			if err := os.Mkdir(item.path, 0700); err != nil {
				return err
			}
			if err := os.Chown(item.path, int(item.uid), -1); err != nil {
				return err
			}
			info, err = os.Lstat(item.path)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("control: invalid private entry state directory")
		}
		owner, err := entryFileUID(info)
		if err != nil || owner != item.uid {
			return errors.New("control: existing entry state owner changed")
		}
	}
	return nil
}
