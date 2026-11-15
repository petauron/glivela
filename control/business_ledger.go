package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	glivela "github.com/petauron/glivela"
)

// Stable logical name inside backups; live archive files are immutable,
// addressed by the ciphertext digest stored in the live ledger.
const businessArchiveFile = "business.archive.json"
const businessArchivePrefix = "business.archive-"

func businessArchiveName(digest string) string { return businessArchivePrefix + digest + ".json" }
func hasBusinessArchive(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() == businessArchiveFile || strings.HasPrefix(entry.Name(), businessArchivePrefix) {
			return true, nil
		}
	}
	return false, nil
}
func readLedgerArchive(directory, digest string) ([]byte, error) {
	if !glivela.ValidIdentity(digest) {
		return nil, errors.New("control: invalid archive reference")
	}
	return readBusinessCheckpointFile(directory, businessArchiveName(digest))
}

func checkpointEnvelope(raw []byte) (stagedImport, error) {
	var state stagedImport
	if decode(bytes.NewReader(raw), &state) != nil || !glivela.ValidIdentifier(state.SnapshotID) || (state.Version != 1 && state.Version != 2) || (state.Version == 1 && state.ArchiveSHA256 != "") || (state.Version == 2 && !glivela.ValidIdentity(state.ArchiveSHA256)) {
		return state, errors.New("control: invalid owned ledger envelope")
	}
	return state, nil
}

// Keep the already authenticated original checkpoint byte for byte. Migration
// writes it first and atomically replaces the live checkpoint last. Startup
// refuses a remaining old ledger beside any archive; explicit recovery must
// distinguish an interrupted migration from replay of committed old bytes.
func prepareOwnedLedgerArchive(directory string, raw []byte, snapshot string) (string, bool, error) {
	state, err := checkpointEnvelope(raw)
	if err != nil || state.SnapshotID != snapshot {
		return "", false, errors.New("control: owned ledger identity changed")
	}
	if state.Version == 1 {
		digest, err := writeImmutableBusinessArchive(directory, raw, nil)
		return digest, true, err
	}
	archive, err := readLedgerArchive(directory, state.ArchiveSHA256)
	if err != nil {
		return "", false, errors.New("control: owned business archive unavailable")
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != state.ArchiveSHA256 {
		return "", false, errors.New("control: immutable business archive changed")
	}
	return state.ArchiveSHA256, false, nil
}

func decodeOwnedBusinessCheckpoint(directory string, raw, key []byte) (glivela.ImportMaterial, string, error) {
	state, err := checkpointEnvelope(raw)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	if state.Version == 1 {
		// An existing archive may be an interrupted migration or a committed
		// ledger replaced by old bytes. Never guess which one, or replay history.
		if found, archiveErr := hasBusinessArchive(directory); archiveErr != nil || found {
			return glivela.ImportMaterial{}, "", errors.New("control: interrupted or rolled-back ledger requires explicit recovery")
		}
		return decodeBusinessCheckpoint(raw, key)
	}

	archive, err := readLedgerArchive(directory, state.ArchiveSHA256)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	return decodeDetachedBusinessCheckpoint(raw, archive, key)
}

// Backup recovery uses this same decoder before creating any restored state.
func decodeDetachedBusinessCheckpoint(raw, archive, key []byte) (glivela.ImportMaterial, string, error) {
	state, err := checkpointEnvelope(raw)
	if err != nil {
		return glivela.ImportMaterial{}, "", err
	}
	if state.Version == 1 {
		return decodeBusinessCheckpoint(raw, key)
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != state.ArchiveSHA256 {
		return glivela.ImportMaterial{}, "", errors.New("control: owned ledger archive digest mismatch")
	}
	source, snapshot, err := decodeBusinessCheckpoint(archive, key)
	if err != nil || snapshot != state.SnapshotID {
		return glivela.ImportMaterial{}, "", errors.New("control: owned ledger archive authentication failed")
	}
	material, err := glivela.OpenImportLedger(state.Sealed, key, snapshot, state.ArchiveSHA256, source)
	return material, snapshot, err
}
