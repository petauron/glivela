package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseSnapshotLimitSeparateFromArchive(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "snapshot")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	size := int64(maxSnapshotBytes + 1)
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := privateFile(path, maxSnapshotBytes); err == nil {
		t.Fatal("archive limit was weakened")
	}
	data, err := privateFile(path, maxDatabaseSnapshotBytes)
	if err != nil || int64(len(data)) != size {
		t.Fatalf("larger database rejected: size=%d error=%v", len(data), err)
	}
	clear(data)
	if err := f.Truncate(maxDatabaseSnapshotBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := privateFile(path, maxDatabaseSnapshotBytes); err == nil {
		t.Fatal("oversized database accepted")
	}
}
