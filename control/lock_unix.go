//go:build linux || darwin

package control

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// LockDirectory prevents two controller/node processes from writing the same
// private state. The kernel releases the lease on process exit; no stale-lock
// deletion or PID guessing is required after a crash.
func LockDirectory(directory string) (func(), error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("control: absolute state directory required")
	}
	for parent := directory; parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("control: unsafe state directory")
		}
		if parent == directory && info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("control: state directory must be private")
		}
	}
	file, err := os.OpenFile(filepath.Join(directory, ".glivela.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, errors.New("control: unsafe state lock")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("control: state already in use")
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
