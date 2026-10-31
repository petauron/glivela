package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// RetireEntry is the explicitly local step before application uninstall.
// The stopped node's directory lease excludes its writer. State is retained.
func RetireEntry(ctx context.Context, directory, distribution string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("control: private entry directory required")
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	info, err := os.Lstat(filepath.Join(directory, "entry-install.json"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
		return errors.New("control: private entry ownership record required")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "entry-install.json"))
	var installed entryInstall
	if err != nil || decode(bytes.NewReader(raw), &installed) != nil || installed.Version != 1 || installed.Container.validate() != nil {
		return errors.New("control: invalid entry ownership record")
	}
	driver, err := ResolveEntryDriver(installed.Container, directory, distribution)
	if err != nil {
		return err
	}
	runtime := &NativeRuntime{Directory: directory, Driver: driver}
	journal, err := runtime.journal()
	if err != nil || journal.Phase != "ready" || journal.Current == nil {
		return errors.New("control: finish entry recovery before retirement")
	}
	if _, err := driver.inspect(ctx, *journal.Current); err != nil {
		return err
	}
	// Persist intent first. A failed stop cannot authorize later activation.
	installed.Retired = true
	raw, err = json.Marshal(installed)
	if err != nil {
		return err
	}
	if err := replacePrivate(directory, "entry-install.json", raw); err != nil {
		return err
	}
	if err := driver.Stop(ctx, *journal.Current); err != nil {
		return err
	}
	state, err := driver.inspect(ctx, *journal.Current)
	if err != nil {
		return err
	}
	if state.State.Running || state.State.Restarting || state.State.Paused || state.State.Pid != 0 || state.State.Status != "exited" && state.State.Status != "created" {
		return errors.New("control: entry stop not confirmed; do not uninstall")
	}
	return nil
}
