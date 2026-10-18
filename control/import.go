package control

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	glivela "github.com/petauron/glivela"
)

type stagedImport struct {
	Version    int    `json:"version"`
	SnapshotID string `json:"snapshotId"`
	Sealed     []byte `json:"sealed"`
}

// StageImport atomically retains accounts, endpoint configuration and immutable
// source history in one private encrypted checkpoint. The temporary transfer
// key is not retained. This offline operation does NOT activate subscriptions,
// accept runtime health or release the old controller's write authority.
func StageImport(directory, snapshotID string, sealed, transferKey, storageKey []byte) error {
	if subtle.ConstantTimeCompare(transferKey, storageKey) == 1 {
		return errors.New("control: transfer and storage keys must differ")
	}
	material, err := glivela.OpenImportMaterial(sealed, transferKey, snapshotID)
	if err != nil {
		return err
	}
	stored, err := glivela.SealImportMaterial(material, storageKey, snapshotID)
	if err != nil {
		return err
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(directory, "business.pending.json")
	if _, err := os.Lstat(path); err == nil {
		previous, id, err := readStagedImport(directory, storageKey)
		if err != nil {
			return err
		}
		if id != snapshotID || !reflect.DeepEqual(previous, material) {
			return errors.New("control: staged import already belongs to another snapshot")
		}
		// Compare the complete decrypted material, including schedules and
		// directional counters outside the account plan's hash. An identical
		// retry must not reseal or rewrite the verified checkpoint.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(stagedImport{Version: 1, SnapshotID: snapshotID, Sealed: stored})
	if err != nil {
		return err
	}
	return replacePrivate(directory, "business.pending.json", raw)
}

// ReadStagedImport verifies the complete durable checkpoint, not live authority.
// Its local lease excludes a running controller; it cannot fence the old writer.
func ReadStagedImport(directory string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	unlock, err := LockDirectory(directory)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	defer unlock()
	return readStagedImport(directory, storageKey)
}

func readStagedImport(directory string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	path := filepath.Join(directory, "business.pending.json")
	info, err := os.Lstat(path)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 90<<20 {
		return glivela.ImportMaterial{}, "", errors.New("control: unsafe staged import")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	var state stagedImport
	if err := json.Unmarshal(raw, &state); err != nil || state.Version != 1 {
		return glivela.ImportMaterial{}, "", errors.New("control: invalid staged import")
	}
	material, err := glivela.OpenImportMaterial(state.Sealed, storageKey, state.SnapshotID)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	return material, state.SnapshotID, nil
}
