package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	glivela "github.com/petauron/glivela"
)

func historyFileOwner(file *os.File, owner os.FileInfo) error {
	if owner == nil {
		return nil
	}
	st, ok := owner.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("control: private file owner unavailable")
	}
	return file.Chown(int(st.Uid), int(st.Gid))
}

// Install an immutable ciphertext without overwriting any existing file. Only
// a fully written, synchronized inode is linked into the archive namespace.
func writeImmutableBusinessArchive(directory string, raw []byte, owner os.FileInfo) (string, error) {
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	name := businessArchiveName(digest)
	if old, err := readBusinessCheckpointFile(directory, name); err == nil {
		if !bytes.Equal(old, raw) {
			return "", errors.New("control: immutable archive collision")
		}
		return digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	f, err := os.CreateTemp(directory, ".business-archive-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = historyFileOwner(f, owner); err != nil {
		return "", err
	}
	if _, err = f.Write(raw); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Link(f.Name(), filepath.Join(directory, name)); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		old, readErr := readBusinessCheckpointFile(directory, name)
		if readErr != nil || !bytes.Equal(old, raw) {
			return "", errors.New("control: immutable archive install changed")
		}
	}
	if err = syncBusinessDirectory(directory); err != nil {
		return "", err
	}
	return digest, nil
}

// ReadOwnedBusinessForHistory authenticates the complete current ledger,
// archive and adoption identity. The offline caller MUST hold LockDirectory
// across this read and its maintenance operation; it is not an HTTP API.
func ReadOwnedBusinessForHistory(directory string, key []byte) (glivela.ImportMaterial, string, [32]byte, error) {
	return readOwnedBusinessVersion(directory, key)
}

// Only this explicit offline operation can replace retained history. It reads
// all live fields itself: callers cannot supply account plans, watermarks,
// credentials, enrollment or runtime state to write back.
// The caller MUST hold LockDirectory and ensure the writers are stopped.
func ReplaceOwnedBusinessHistory(directory string, key []byte, expected [32]byte, source json.RawMessage) error {
	material, snapshot, observed, err := readOwnedBusinessVersion(directory, key)
	if err != nil {
		return err
	}
	if observed != expected {
		return errors.New("control: business writer changed during history maintenance")
	}
	owner, err := os.Lstat(filepath.Join(directory, "business.json"))
	if err != nil {
		return err
	}
	if err = checkHistoryKey(directory, key); err != nil {
		return err
	}
	before, err := readBusinessCheckpointFile(directory, "business.json")
	if err != nil {
		return err
	}
	state, err := checkpointEnvelope(before)
	if err != nil {
		return err
	}
	next := material
	next.RetainedSource = bytes.Clone(source)
	// This also checks the original snapshot/source identity against the supplied
	// history header; every other live field is the authenticated current value.
	sealed, err := glivela.SealImportMaterial(next, key, snapshot)
	if err != nil {
		return err
	}
	archiveRaw, err := json.Marshal(stagedImport{Version: 1, SnapshotID: snapshot, Sealed: sealed})
	if err != nil {
		return err
	}
	digest := state.ArchiveSHA256
	same := state.Version == 2 && bytes.Equal(material.RetainedSource, source)
	if !same {
		if digest, err = writeImmutableBusinessArchive(directory, archiveRaw, owner); err != nil {
			return err
		}
	}
	garbage, err := unreferencedHistoryArchives(directory, key, snapshot, material, digest)
	if err != nil {
		return err
	}
	if !same {
		ledger, sealErr := glivela.SealImportLedger(next, key, snapshot, digest)
		if sealErr != nil {
			return sealErr
		}
		raw, encodeErr := json.Marshal(stagedImport{Version: 2, SnapshotID: snapshot, Sealed: ledger, ArchiveSHA256: digest})
		if encodeErr != nil {
			return encodeErr
		}
		if err = replaceHistoryLedger(directory, key, expected, raw, owner); err != nil {
			return err
		}
	}
	// A completed manifest commit is durable before any old archive is removed.
	// Interrupted cleanup leaves only unreferenced files, never an unreadable pair.
	for _, name := range garbage {
		if err = os.Remove(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	return syncBusinessDirectory(directory)
}

func checkHistoryKey(directory string, key []byte) error {
	disk, err := readBusinessKey(filepath.Join(directory, "business.key"))
	if err != nil {
		return err
	}
	defer clear(disk)
	if !bytes.Equal(disk, key) {
		return errors.New("control: business storage key changed")
	}
	return nil
}
func replaceHistoryLedger(directory string, key []byte, expected [32]byte, raw []byte, owner os.FileInfo) error {
	f, err := os.CreateTemp(directory, ".history-ledger-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = historyFileOwner(f, owner); err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	before, err := readBusinessCheckpointFile(directory, "business.json")
	if err != nil || sha256.Sum256(before) != expected {
		return errors.New("control: business writer changed during history maintenance")
	}
	if err = checkHistoryKey(directory, key); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(directory, "business.json")); err != nil {
		return err
	}
	return syncBusinessDirectory(directory)
}
func unreferencedHistoryArchives(directory string, key []byte, snapshot string, live glivela.ImportMaterial, keep string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, businessArchivePrefix) {
			continue
		}
		digest := strings.TrimSuffix(strings.TrimPrefix(name, businessArchivePrefix), ".json")
		if !glivela.ValidIdentity(digest) || name != businessArchiveName(digest) {
			return nil, errors.New("control: unknown business archive retained for review")
		}
		if digest == keep {
			continue
		}
		raw, err := readBusinessCheckpointFile(directory, name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != digest {
			return nil, errors.New("control: unreferenced archive digest mismatch")
		}
		m, id, err := decodeBusinessCheckpoint(raw, key)
		if err != nil || id != snapshot || m.SourceSHA256 != live.SourceSHA256 || m.Ownership == nil || live.Ownership == nil || *m.Ownership != *live.Ownership {
			return nil, errors.New("control: unreferenced archive identity differs; retained for review")
		}
		names = append(names, name)
	}
	return names, nil
}
