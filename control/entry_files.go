package control

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func entryPathsOverlap(a, b string) bool {
	inside := func(parent, child string) bool {
		r, err := filepath.Rel(parent, child)
		return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
	}
	return inside(a, b) || inside(b, a)
}

func (d *EntryDriver) checkDirectories() error {
	if d.Binding() == "" {
		return errors.New("control: unsafe entry directories")
	}
	for _, item := range []struct {
		path string
		uid  uint32
	}{{d.Directory, uint32(os.Geteuid())}, {d.Container.ConfigurationDirectory, d.Container.UID}} {
		for path := item.path; path != "/"; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return errors.New("control: unsafe entry directory ancestry")
			}
			if path == item.path {
				uid, err := entryFileUID(info)
				if err != nil || uid != item.uid || info.Mode().Perm()&0077 != 0 {
					return errors.New("control: private entry directory owner differs")
				}
			}
		}
	}
	journal, err := os.Stat(d.Directory)
	worker, workerErr := os.Stat(d.Container.ConfigurationDirectory)
	if err != nil || workerErr != nil || os.SameFile(journal, worker) {
		return errors.New("control: entry worker and private journal must be separate")
	}
	return nil
}

func (d *EntryDriver) checkWorkerConfig(desired Desired, previous *Desired) error {
	path := filepath.Join(d.Container.ConfigurationDirectory, "config.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("control: unowned entry worker configuration")
	}
	uid, err := entryFileUID(info)
	if err != nil || uid != d.Container.UID {
		return errors.New("control: entry worker configuration owner differs")
	}
	if verifyEntryConfigFile(path, desired.Config) == nil || previous != nil && verifyEntryConfigFile(path, previous.Config) == nil {
		return nil
	}
	return errors.New("control: entry worker configuration is not a known revision")
}

func (d *EntryDriver) checkKnownWorkerConfig(desired Desired) error {
	state, err := (&NativeRuntime{Directory: d.Directory, Driver: d}).journal()
	if errors.Is(err, os.ErrNotExist) {
		return d.checkWorkerConfig(desired, nil)
	}
	if err != nil {
		return err
	}
	for _, known := range []*Desired{state.Current, state.Candidate} {
		if known == nil {
			continue
		}
		if err := d.plan(*known); err != nil {
			return err
		}
		if d.checkWorkerConfig(desired, known) == nil {
			return nil
		}
	}
	return d.checkWorkerConfig(desired, nil)
}

func (d *EntryDriver) writeWorkerConfig(raw []byte) error {
	if err := d.checkDirectories(); err != nil {
		return err
	}
	file, err := os.CreateTemp(d.Container.ConfigurationDirectory, ".glivela-config-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	uid, err := entryFileUID(info)
	if err != nil {
		return err
	}
	if uid != d.Container.UID {
		if err := file.Chown(int(d.Container.UID), -1); err != nil {
			return errors.New("control: cannot retain entry worker file ownership")
		}
	}
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), filepath.Join(d.Container.ConfigurationDirectory, "config.json")); err != nil {
		return err
	}
	directory, err := os.Open(d.Container.ConfigurationDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
