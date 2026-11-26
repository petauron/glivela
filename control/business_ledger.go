package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	glivela "github.com/petauron/glivela"
)

// Stable logical name inside backups; live archive files are immutable,
// addressed by the ciphertext digest stored in the live ledger.
const businessArchiveFile = "business.archive.json"
const businessArchivePrefix = "business.archive-"

type archiveFileStamp struct {
	dev     uint64
	ino     uint64
	size    int64
	mode    os.FileMode
	modTime int64
}

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

func archiveStampFromInfo(info os.FileInfo) (archiveFileStamp, error) {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 90<<20 {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	return archiveFileStamp{
		dev:     uint64(st.Dev),
		ino:     uint64(st.Ino),
		size:    info.Size(),
		mode:    info.Mode(),
		modTime: info.ModTime().UnixNano(),
	}, nil
}

func statLedgerArchive(directory, digest string) (archiveFileStamp, error) {
	if !glivela.ValidIdentity(digest) {
		return archiveFileStamp{}, errors.New("control: invalid archive reference")
	}
	info, err := os.Lstat(filepath.Join(directory, businessArchiveName(digest)))
	if err != nil {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	return archiveStampFromInfo(info)
}

func verifyLedgerArchive(directory, digest string) (archiveFileStamp, error) {
	if !glivela.ValidIdentity(digest) {
		return archiveFileStamp{}, errors.New("control: invalid archive reference")
	}
	path := filepath.Join(directory, businessArchiveName(digest))
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	stamp, err := archiveStampFromInfo(lstatInfo)
	if err != nil {
		return archiveFileStamp{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(lstatInfo, openedInfo) {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	openedStamp, err := archiveStampFromInfo(openedInfo)
	if err != nil || openedStamp != stamp {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, 90<<20+1))
	if err != nil || written > 90<<20 {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return archiveFileStamp{}, errors.New("control: owned business archive unavailable")
	}
	afterStamp, err := archiveStampFromInfo(afterInfo)
	if err != nil || afterStamp != stamp {
		return archiveFileStamp{}, errors.New("control: immutable business archive changed")
	}
	if hex.EncodeToString(hasher.Sum(nil)) != digest {
		return archiveFileStamp{}, errors.New("control: immutable business archive changed")
	}
	return stamp, nil
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
func prepareOwnedLedgerArchive(directory string, raw []byte, snapshot string) (string, bool, archiveFileStamp, error) {
	state, err := checkpointEnvelope(raw)
	if err != nil || state.SnapshotID != snapshot {
		return "", false, archiveFileStamp{}, errors.New("control: owned ledger identity changed")
	}
	if state.Version == 1 {
		digest, err := writeImmutableBusinessArchive(directory, raw, nil)
		if err != nil {
			return "", true, archiveFileStamp{}, err
		}
		stamp, err := statLedgerArchive(directory, digest)
		if err != nil {
			return "", true, archiveFileStamp{}, err
		}
		return digest, true, stamp, nil
	}
	stamp, err := verifyLedgerArchive(directory, state.ArchiveSHA256)
	if err != nil {
		return "", false, archiveFileStamp{}, err
	}
	return state.ArchiveSHA256, false, stamp, nil
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
