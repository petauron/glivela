package glivela

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// The small live ledger authenticates the exact immutable archive ciphertext.
// Import/export remains self-contained; only owned controller storage uses this
// detached form. Never reconstruct missing history from a different snapshot.
const importLedgerContext = "glivela-owned-ledger-v2:"

func SealImportLedger(m ImportMaterial, key []byte, snapshotID, archiveSHA256 string) ([]byte, error) {
	source, sourceErr := m.sourceHeader()
	if !ValidIdentity(archiveSHA256) || sourceErr != nil || m.validateWithSource(source) != nil {
		return nil, errors.New("glivela: invalid owned ledger")
	}
	if id, _ := m.sourceSnapshotHeader(source); id != snapshotID {
		return nil, errors.New("glivela: owned ledger source identity mismatch")
	}
	aead, err := importCipher(key, snapshotID)
	if err != nil {
		return nil, err
	}
	type material ImportMaterial
	// Override the embedded field to omit the large immutable source only.
	raw, err := json.Marshal(struct {
		material
		RetainedSource json.RawMessage `json:"retainedSource,omitempty"`
	}{material: material(m)})
	if err != nil || len(raw) > maxImportMaterial {
		return nil, errors.New("glivela: owned ledger too large")
	}
	defer clear(raw)
	return aead.Seal(nil, nil, raw, []byte(importLedgerContext+snapshotID+":"+archiveSHA256)), nil
}

func OpenImportLedger(sealed, key []byte, snapshotID, archiveSHA256 string, archive ImportMaterial) (ImportMaterial, error) {
	invalid := errors.New("glivela: owned ledger authentication or source mismatch")
	if !ValidIdentity(archiveSHA256) {
		return ImportMaterial{}, invalid
	}
	if source, _ := archive.sourceSnapshot(); source != snapshotID {
		return ImportMaterial{}, invalid
	}
	aead, err := importCipher(key, snapshotID)
	if err != nil || len(sealed) > maxImportMaterial+64 {
		return ImportMaterial{}, invalid
	}
	raw, err := aead.Open(nil, nil, sealed, []byte(importLedgerContext+snapshotID+":"+archiveSHA256))
	if err != nil {
		return ImportMaterial{}, invalid
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var m ImportMaterial
	var extra any
	if d.Decode(&m) != nil || d.Decode(&extra) != io.EOF || len(m.RetainedSource) != 0 || m.SourceSHA256 != archive.SourceSHA256 {
		return ImportMaterial{}, invalid
	}
	m.RetainedSource = archive.RetainedSource
	m.sourceCache = archive.sourceCache
	if m.cacheSource() != nil || m.Validate() != nil {
		return ImportMaterial{}, invalid
	}
	if source, _ := m.sourceSnapshot(); source != snapshotID {
		return ImportMaterial{}, invalid
	}
	return m, nil
}
