package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const legacyLandingJournal = "/var/lib/vastora/landing-host.json"

var legacyLandingFiles = []string{
	"/etc/vastora-landing/danted.conf", "/etc/vastora-landing/danted",
	"/etc/vastora-landing/Dante-LICENSE", "/etc/vastora-landing/Dante-NOTICE",
	"/etc/vastora-landing/resolv.conf", "/etc/vastora-landing/nsswitch.conf",
	"/etc/systemd/system/vastora-landing.service",
	"/etc/systemd/system/vastora-landing-firewall.service",
}

// LegacyLandingSnapshot is private migration evidence, not a node-channel
// message. Preserve the original ownership journal and exact file bytes; do not
// regenerate old configuration when restoring a failed first-time cutover.
type LegacyLandingSnapshot struct {
	Version  int                        `json:"version"`
	NodeID   string                     `json:"nodeId"`
	Revision uint64                     `json:"revision"`
	Journal  []byte                     `json:"journal"`
	Files    map[string]LegacyOwnedFile `json:"files"`
}

type LegacyOwnedFile struct {
	Contents []byte `json:"contents"`
	Mode     uint32 `json:"mode"`
}

// SnapshotLegacyLanding only reads the fixed previous installation. It neither
// fences the previous writer nor authorizes activating Xray. Those are separate
// cutover preconditions; a successful snapshot must never imply migration success.
func SnapshotLegacyLanding(nodeID string) (LegacyLandingSnapshot, error) {
	return snapshotLegacyLanding("/", nodeID, 0)
}

// BackupLegacyLanding creates a new private recovery checkpoint. It never
// overwrites an earlier backup and does not change the original installation.
func BackupLegacyLanding(directory, nodeID string) (string, error) {
	snapshot, err := SnapshotLegacyLanding(nodeID)
	if err != nil {
		return "", err
	}
	return backupLegacyLanding(directory, snapshot)
}

func backupLegacyLanding(directory string, snapshot LegacyLandingSnapshot) (string, error) {
	if !filepath.IsAbs(directory) {
		return "", errors.New("control: private backup directory required")
	}
	for parent := directory; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || parent == directory && info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return "", errors.New("control: unsafe backup directory")
		}
		if parent == "/" {
			break
		}
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	checkpoint, err := os.MkdirTemp(directory, "legacy-landing-")
	if err != nil {
		return "", err
	}
	// Failed checkpoints are retained for diagnosis, but never returned as a
	// completed backup. replacePrivate syncs both bytes and the checkpoint dir.
	if err := replacePrivate(checkpoint, "snapshot.json", raw); err != nil {
		return "", err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return "", err
	}
	return filepath.Join(checkpoint, "snapshot.json"), nil
}

func snapshotLegacyLanding(root, nodeID string, owner uint32) (LegacyLandingSnapshot, error) {
	var result LegacyLandingSnapshot
	if nodeID == "" || !filepath.IsAbs(root) {
		return result, errors.New("control: legacy identity required")
	}
	read := func(name string, limit int64) ([]byte, uint32, error) {
		path := filepath.Join(root, name)
		for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return nil, 0, errors.New("control: unsafe legacy directory")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != owner && stat.Uid != 0 {
				return nil, 0, errors.New("control: unowned legacy directory")
			}
			if parent == "/" {
				break
			}
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
			return nil, 0, errors.New("control: unsafe or missing legacy file")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != owner {
			return nil, 0, errors.New("control: unowned legacy file")
		}
		raw, err := os.ReadFile(path)
		return raw, uint32(info.Mode().Perm()), err
	}
	journal, _, err := read(legacyLandingJournal, 128<<10)
	if err != nil {
		return result, err
	}
	var metadata struct {
		NodeID         string            `json:"nodeId"`
		UID            uint32            `json:"uid"`
		Revision       uint64            `json:"revision"`
		Files          map[string]string `json:"files"`
		PendingFiles   map[string]string `json:"pendingFiles"`
		Policy         json.RawMessage   `json:"policy"`
		PreviousPolicy json.RawMessage   `json:"previousPolicy"`
		Removed        bool              `json:"removed"`
		PlanDigest     string            `json:"planDigest"`
	}
	if json.Unmarshal(journal, &metadata) != nil || metadata.NodeID != nodeID || metadata.UID == 0 || metadata.Revision == 0 || metadata.Removed || len(metadata.PendingFiles) != 0 || len(metadata.PreviousPolicy) != 0 && string(metadata.PreviousPolicy) != "null" || len(metadata.Policy) == 0 || string(metadata.Policy) == "null" {
		return result, errors.New("control: legacy operation incomplete or identity differs")
	}
	if len(metadata.Files) != len(legacyLandingFiles) {
		return result, errors.New("control: incomplete legacy ownership inventory")
	}
	result = LegacyLandingSnapshot{Version: 1, NodeID: nodeID, Revision: metadata.Revision, Journal: journal, Files: make(map[string]LegacyOwnedFile)}
	for _, name := range legacyLandingFiles {
		limit := int64(128 << 10)
		if name == "/etc/vastora-landing/danted" {
			limit = 64 << 20
		}
		raw, mode, err := read(name, limit)
		if err != nil {
			return LegacyLandingSnapshot{}, err
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != metadata.Files[name] {
			return LegacyLandingSnapshot{}, errors.New("control: legacy resource changed outside its owner")
		}
		result.Files[name] = LegacyOwnedFile{Contents: raw, Mode: mode}
	}
	// Detect a concurrent old writer. A later cutover still needs an explicit
	// writer fence and revalidation; this read-only check is not that fence.
	after, _, err := read(legacyLandingJournal, 128<<10)
	if err != nil || string(after) != string(journal) {
		return LegacyLandingSnapshot{}, errors.New("control: legacy writer changed during snapshot")
	}
	return result, nil
}
