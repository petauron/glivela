package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	glivela "github.com/petauron/glivela"
)

// This durable intent prevents a lost owned file from being mistaken for a
// never-adopted staging directory. Presence alone cannot grant authority.
type businessAdoptionIntent struct {
	Version       int    `json:"version"`
	SnapshotID    string `json:"snapshotId"`
	SourceSHA256  string `json:"sourceSha256"`
	CaptureSHA256 string `json:"captureSha256"`
}

func readBusinessAdoptionIntent(directory string) (businessAdoptionIntent, error) {
	var intent businessAdoptionIntent
	path := filepath.Join(directory, "business.adoption.json")
	info, err := os.Lstat(path)
	if err != nil {
		return intent, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return intent, errors.New("control: unsafe business adoption intent")
	}
	raw, err := os.ReadFile(path)
	if err != nil || decode(bytes.NewReader(raw), &intent) != nil || intent.Version != 1 || !glivela.ValidIdentifier(intent.SnapshotID) || !glivela.ValidIdentity(intent.SourceSHA256) || !glivela.ValidIdentity(intent.CaptureSHA256) {
		return businessAdoptionIntent{}, errors.New("control: invalid business adoption intent")
	}
	return intent, nil
}

func businessAdoptionStarted(directory string) (bool, error) {
	for _, name := range []string{"business.json", "business.adoption.json"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// AdoptStagedBusiness is a local, offline commit used ONLY after the one-time
// tool has independently checked the final backup and still-stopped old writer.
// This is not exposed to HTTP clients. Possessing a staged archive or JSON
// evidence alone is not permission to invoke it. The private directory/key are
// controlled by the local operator; no platform key is retained in owned data.
//
// The pending checkpoint remains immutable recovery evidence, never a fallback
// configuration source after business.json exists. This data-ownership commit
// neither accepts routes nor retires services or changes the generic Agent.
func AdoptStagedBusiness(directory, snapshotID string, ownership glivela.BusinessOwnership, storageKey []byte) error {
	if ownership.Validate(ownership.SourceSHA256) != nil {
		return errors.New("control: final ownership evidence required")
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(directory, "business.json")
	if _, err := os.Lstat(path); err == nil {
		current, id, err := readOwnedBusiness(directory, storageKey)
		if err != nil || id != snapshotID || current.Ownership == nil || *current.Ownership != ownership {
			return errors.New("control: existing business ownership differs or is invalid")
		}
		// An acknowledged retry must also confirm directory durability. Never
		// reseal or replay staged account/ledger values over owned updates.
		return syncBusinessDirectory(directory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	material, id, err := readStagedImport(directory, storageKey)
	if err != nil {
		return err
	}
	if id != snapshotID || material.SourceSHA256 != ownership.SourceSHA256 {
		return errors.New("control: final snapshot differs from staged business")
	}
	material.Ownership = &ownership
	sealed, err := glivela.SealImportMaterial(material, storageKey, snapshotID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(stagedImport{Version: 1, SnapshotID: snapshotID, Sealed: sealed})
	if err != nil {
		return err
	}
	intent := businessAdoptionIntent{Version: 1, SnapshotID: snapshotID, SourceSHA256: ownership.SourceSHA256, CaptureSHA256: ownership.CaptureSHA256}
	_, err = os.Lstat(filepath.Join(directory, "business.adoption.json"))
	if errors.Is(err, os.ErrNotExist) {
		intentRaw, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		if err := writeNewBusinessFile(directory, "business.adoption.json", intentRaw); err != nil {
			return err
		}
	} else {
		// A missing owned file after an earlier intent may represent lost LIVE
		// data, not merely an interrupted first write. Never recreate it from
		// an older staging snapshot and silently roll back account or usage edits.
		return errors.New("control: adoption started without owned data; explicit recovery required")
	}
	return writeNewBusinessFile(directory, "business.json", raw)
}

func writeNewBusinessFile(directory, name string, raw []byte) error {
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	// Keep failed partial owned state for explicit inspection. Starting the
	// controller must refuse it, not silently restore old pending data.
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		file.Close()
		return errors.New("control: business ownership write failed")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncBusinessDirectory(directory)
}

func syncBusinessDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
