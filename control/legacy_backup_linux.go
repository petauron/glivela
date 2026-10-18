package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// loadLegacyBackup validates every retained resource before recovery may
// execute anything. It returns an open, verified recovery binary, preventing
// a pathname replacement between verification and execution by the caller.
func loadLegacyBackup(path, nodeID string, owner uint32) (LegacyLandingSnapshot, *os.File, error) {
	var snapshot LegacyLandingSnapshot
	refuse := func() (LegacyLandingSnapshot, *os.File, error) {
		return LegacyLandingSnapshot{}, nil, errors.New("control: invalid legacy recovery checkpoint")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "snapshot.json" {
		return refuse()
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return refuse()
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != owner && stat.Uid != 0 || parent == filepath.Dir(path) && info.Mode().Perm()&0077 != 0 {
			return refuse()
		}
		if parent == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return refuse()
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return refuse()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 96<<20 {
		return refuse()
	}
	if decode(io.LimitReader(file, (96<<20)+1), &snapshot) != nil || snapshot.Version != 1 || snapshot.NodeID != nodeID || nodeID == "" || snapshot.Revision == 0 {
		return refuse()
	}
	var journal struct {
		NodeID         string            `json:"nodeId"`
		Revision       uint64            `json:"revision"`
		Files          map[string]string `json:"files"`
		UID            uint32            `json:"uid"`
		Removed        bool              `json:"removed"`
		PendingFiles   map[string]string `json:"pendingFiles"`
		PreviousPolicy json.RawMessage   `json:"previousPolicy"`
		Policy         json.RawMessage   `json:"policy"`
	}
	if json.Unmarshal(snapshot.Journal, &journal) != nil || journal.NodeID != nodeID || journal.Revision != snapshot.Revision || len(journal.Files) != len(legacyLandingFiles) || len(snapshot.Files) != len(legacyLandingFiles) {
		return refuse()
	}
	if journal.UID == 0 || journal.Removed || len(journal.PendingFiles) != 0 || len(journal.Policy) == 0 || string(journal.Policy) == "null" || len(journal.PreviousPolicy) != 0 && string(journal.PreviousPolicy) != "null" {
		return refuse()
	}
	for _, name := range legacyLandingFiles {
		resource, exists := snapshot.Files[name]
		limit := 128 << 10
		if name == "/etc/vastora-landing/danted" {
			limit = 64 << 20
		}
		digest := sha256.Sum256(resource.Contents)
		if !exists || len(resource.Contents) > limit || resource.Mode > 0777 || resource.Mode&0022 != 0 || journal.Files[name] != hex.EncodeToString(digest[:]) {
			return refuse()
		}
	}
	programPath, err := legacyFirewallExecutable(snapshot.Files["/etc/systemd/system/vastora-landing-firewall.service"].Contents)
	if err != nil || programPath != snapshot.RecoveryProgram.Path {
		return refuse()
	}
	program, err := openLegacyRecoveryProgram(filepath.Join(filepath.Dir(path), "recovery-program"), owner)
	if err != nil {
		return refuse()
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(program, (128<<20)+1))
	if err != nil || size != snapshot.RecoveryProgram.Size || hex.EncodeToString(hash.Sum(nil)) != snapshot.RecoveryProgram.SHA256 {
		program.Close()
		return refuse()
	}
	if _, err := program.Seek(0, io.SeekStart); err != nil {
		program.Close()
		return refuse()
	}
	if _, _, err := snapshot.migrationPlan(); err != nil {
		program.Close()
		return LegacyLandingSnapshot{}, nil, err
	}
	return snapshot, program, nil
}
