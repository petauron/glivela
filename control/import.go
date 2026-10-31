package control

import (
	"bytes"
	"crypto/sha256"
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
	if material.Ownership != nil {
		return errors.New("control: a transfer archive cannot grant business authority")
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	store, err := OpenStore(filepath.Join(directory, "nodes.json"))
	if err != nil {
		return err
	}
	if err := bindExistingBusinessRuntime(store, &material); err != nil {
		return err
	}
	stored, err := glivela.SealImportMaterial(material, storageKey, snapshotID)
	if err != nil {
		return err
	}
	if started, err := businessAdoptionStarted(directory); err != nil || started {
		return errors.New("control: owned business state cannot be reinitialized by staging")
	}
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
	if started, err := businessAdoptionStarted(directory); err != nil || started {
		return glivela.ImportMaterial{}, "", errors.New("control: staged data is no longer the current business state")
	}
	return readStagedImport(directory, storageKey)
}

func readStagedImport(directory string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	material, snapshot, err := readBusinessCheckpoint(directory, "business.pending.json", storageKey)
	if err == nil && material.Ownership != nil {
		return glivela.ImportMaterial{}, "", errors.New("control: authority in staged import is invalid")
	}
	return material, snapshot, err
}

func readOwnedBusiness(directory string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	material, snapshot, _, err := readOwnedBusinessVersion(directory, storageKey)
	return material, snapshot, err
}

// The fingerprint covers the exact bytes authenticated by this load. It is
// only an in-memory version fence, never a substitute for startup decryption.
func readOwnedBusinessVersion(directory string, storageKey []byte) (glivela.ImportMaterial, string, [32]byte, error) {
	raw, err := readBusinessCheckpointFile(directory, "business.json")
	if err != nil {
		return glivela.ImportMaterial{}, "", [32]byte{}, err
	}
	material, snapshot, err := decodeBusinessCheckpoint(raw, storageKey)
	if err != nil {
		return glivela.ImportMaterial{}, "", [32]byte{}, err
	}
	intent, intentErr := readBusinessAdoptionIntent(directory)
	if material.Ownership == nil || intentErr != nil || intent.SnapshotID != snapshot || intent.SourceSHA256 != material.SourceSHA256 || intent.CaptureSHA256 != material.Ownership.CaptureSHA256 {
		return glivela.ImportMaterial{}, "", [32]byte{}, errors.New("control: owned business checkpoint requires matching authenticated ownership")
	}
	return material, snapshot, sha256.Sum256(raw), nil
}

func readBusinessCheckpoint(directory, name string, storageKey []byte) (glivela.ImportMaterial, string, error) {
	raw, err := readBusinessCheckpointFile(directory, name)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	return decodeBusinessCheckpoint(raw, storageKey)
}

func readBusinessCheckpointFile(directory, name string) ([]byte, error) {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 90<<20 {
		return nil, errors.New("control: unsafe staged import")
	}
	return os.ReadFile(path)
}

func decodeBusinessCheckpoint(raw, storageKey []byte) (glivela.ImportMaterial, string, error) {
	var state stagedImport
	if err := decode(bytes.NewReader(raw), &state); err != nil || state.Version != 1 {
		return glivela.ImportMaterial{}, "", errors.New("control: invalid staged import")
	}
	material, err := glivela.OpenImportMaterial(state.Sealed, storageKey, state.SnapshotID)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	return material, state.SnapshotID, nil
}
