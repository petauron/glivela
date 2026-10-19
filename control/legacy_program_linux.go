package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// This is a private recovery dependency, not a compatibility runtime or a
// second controller. It is never started by snapshot/backup operations.
type LegacyRecoveryProgram struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func legacyFirewallExecutable(unit []byte) (string, error) {
	const prefix = "# Managed by Vastora\n[Unit]\nDescription=Vastora landing firewall\nBefore=vastora-landing.service\nAfter=tailscaled.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart="
	const suffix = " agent landing-firewall\n"
	text := string(unit)
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
		return "", errors.New("control: unsupported legacy firewall unit")
	}
	path := strings.TrimSuffix(strings.TrimPrefix(text, prefix), suffix)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, " \t\r\n%$\\\"'") {
		return "", errors.New("control: unsafe legacy firewall executable")
	}
	return path, nil
}

func openLegacyRecoveryProgram(path string, owner uint32) (*os.File, error) {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, errors.New("control: unsafe recovery program directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != owner && stat.Uid != 0 {
			return nil, errors.New("control: unowned recovery program directory")
		}
		if parent == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("control: recovery program unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0100 == 0 || info.Size() < 4 || info.Size() > 128<<20 {
		file.Close()
		return nil, errors.New("control: unsafe recovery program")
	}
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil || string(magic[:]) != "\x7fELF" {
		file.Close()
		return nil, errors.New("control: recovery program is not native ELF")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func inspectLegacyRecoveryProgram(root string, owner uint32, unit []byte) (LegacyRecoveryProgram, string, error) {
	path, err := legacyFirewallExecutable(unit)
	if err != nil {
		return LegacyRecoveryProgram{}, "", err
	}
	source := filepath.Join(root, path)
	file, err := openLegacyRecoveryProgram(source, owner)
	if err != nil {
		return LegacyRecoveryProgram{}, "", err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, (128<<20)+1))
	if err != nil || size > 128<<20 {
		return LegacyRecoveryProgram{}, "", errors.New("control: cannot hash recovery program")
	}
	return LegacyRecoveryProgram{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size}, source, nil
}

func copyLegacyRecoveryProgram(directory string, snapshot LegacyLandingSnapshot) error {
	if snapshot.programSource == "" {
		return errors.New("control: recovery program source not verified")
	}
	source, err := openLegacyRecoveryProgram(snapshot.programSource, snapshot.programOwner)
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(directory, "recovery-program"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		return err
	}
	defer target.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, (128<<20)+1))
	if err != nil || size != snapshot.RecoveryProgram.Size || hex.EncodeToString(hash.Sum(nil)) != snapshot.RecoveryProgram.SHA256 {
		return errors.New("control: recovery program changed during backup")
	}
	return target.Sync()
}
