//go:build linux || darwin

package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryLease(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	unlock, err := LockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := LockDirectory(dir); err == nil {
		other()
		t.Fatal("second writer accepted")
	}
	unlock()
	unlock, err = LockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
