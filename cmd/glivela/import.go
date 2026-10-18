package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/petauron/glivela/control"
)

// Keys are read from private files, never command arguments or environment
// values. Staging only writes the encrypted pending checkpoint; it does not
// start a node, change subscriptions or release the old controller's authority.
func stageAccounts(path, snapshot, directory, transferKeyPath, storageKeyPath string) error {
	read := func(path string, limit int64) ([]byte, error) {
		if !filepath.IsAbs(path) {
			return nil, errors.New("absolute import path required")
		}
		for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return nil, errors.New("unsafe import parent")
			}
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
			return nil, errors.New("unsafe import source")
		}
		return os.ReadFile(path)
	}
	transferKey, err := read(transferKeyPath, 32)
	if err != nil {
		return err
	}
	defer clear(transferKey)
	storageKey, err := read(storageKeyPath, 32)
	if err != nil {
		return err
	}
	defer clear(storageKey)
	sealed, err := read(path, (64<<20)+64)
	if err != nil {
		return err
	}
	return control.StageAccountImport(directory, snapshot, sealed, transferKey, storageKey)
}
