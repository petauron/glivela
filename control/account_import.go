package control

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	glivela "github.com/petauron/glivela"
)

type stagedAccounts struct {
	Version    int    `json:"version"`
	SnapshotID string `json:"snapshotId"`
	Sealed     []byte `json:"sealed"`
}

// StageAccountImport durably transfers existing identities and usage into the
// controller's private storage, encrypted with its own key rather than retaining
// the temporary transfer key. It is an offline, local import operation. Staging
// does NOT transfer authority: routes/history and the old-writer fence must be
// verified before these accounts may be used by the business API.
func StageAccountImport(directory, snapshotID string, sealed, transferKey, storageKey []byte) error {
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
	path := filepath.Join(directory, "accounts.pending.json")
	if _, err := os.Lstat(path); err == nil {
		previous, id, err := readStagedAccounts(directory, storageKey)
		if err != nil {
			return err
		}
		if id != snapshotID || previous.Plan.SHA256 != material.Plan.SHA256 {
			return errors.New("control: staged account import already belongs to another snapshot")
		}
		// The authenticated plan binds every token/credential identity and
		// usage baseline. Do not reseal or rewrite a verified identical retry.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(stagedAccounts{Version: 1, SnapshotID: snapshotID, Sealed: stored})
	if err != nil {
		return err
	}
	return replacePrivate(directory, "accounts.pending.json", raw)
}

// ReadStagedAccounts verifies the encrypted durable checkpoint, not live
// subscription authority. The local directory lock excludes a simultaneous
// import and a running controller; neither lock fences the old Vastora writer.
func ReadStagedAccounts(directory string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	unlock, err := LockDirectory(directory)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	defer unlock()
	return readStagedAccounts(directory, storageKey)
}

func readStagedAccounts(directory string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	path := filepath.Join(directory, "accounts.pending.json")
	info, err := os.Lstat(path)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 90<<20 {
		return glivela.ImportMaterial{}, "", errors.New("control: unsafe staged account import")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	var state stagedAccounts
	if err := json.Unmarshal(raw, &state); err != nil || state.Version != 1 {
		return glivela.ImportMaterial{}, "", errors.New("control: invalid staged account import")
	}
	material, err := glivela.OpenImportMaterial(state.Sealed, storageKey, state.SnapshotID)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	return material, state.SnapshotID, nil
}
