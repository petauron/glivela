package control

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// A local administrator may preserve only a resolver bind mount across package
// upgrades. This is not a general drop-in escape hatch: the original unit hash,
// worker identity and loaded-state checks remain mandatory.
func (d SystemdDriver) verifyDNSOverride(ctx context.Context, raw string) (string, error) {
	invalid := errors.New("control: unverified service DNS override")
	const prefix = "DropInPaths="
	value := ""
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, prefix) {
			value = strings.TrimPrefix(line, prefix)
		}
	}
	if value == "" {
		return raw, nil
	}
	unit, err := d.installationNames()
	if err != nil || !filepath.IsAbs(d.Installation) || filepath.Clean(d.Installation) != d.Installation || !validMaintenanceName(d.Service) {
		return "", invalid
	}
	override := unit + ".d/90-preserve-dns.conf"
	resolver := filepath.Join(filepath.Dir(d.Installation), d.Service, "reality-resolv.conf")
	if value != override || strings.ContainsAny(resolver, " \t\r\n%:\\\"") {
		return "", invalid
	}
	content, err := readRootDNSFile(override)
	if err != nil || string(content) != "[Service]\nBindReadOnlyPaths="+resolver+":/etc/resolv.conf\n" {
		return "", invalid
	}
	if _, err := readRootDNSFile(resolver); err != nil {
		return "", invalid
	}
	// Verify the effective mount, not just the on-disk declaration. No extra
	// mounts, writable binds or changes to other service directives are allowed.
	loaded, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", d.Unit, "--property=BindReadOnlyPaths", "--value").Output()
	if err != nil || strings.TrimSpace(string(loaded)) != resolver+":/etc/resolv.conf:rbind" {
		return "", invalid
	}
	return strings.ReplaceAll(raw, prefix+override+"\n", prefix+"\n"), nil
}

func readRootDNSFile(path string) ([]byte, error) {
	return readOwnedDNSFile(path, 0)
}

// systemd-resolved legitimately owns its runtime resolver files. Trust that
// named OS principal only at these exact locations, not arbitrary user files.
// The configured resolver is still read without changing DNS or the unit.
func readExistingEntryDNSFile(path string) ([]byte, error) {
	var resolverUID uint32
	if path == "/run/systemd/resolve/stub-resolv.conf" || path == "/run/systemd/resolve/resolv.conf" {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		owner, err := entryFileUID(info)
		if err != nil {
			return nil, err
		}
		if owner != 0 {
			principal, err := user.Lookup("systemd-resolve")
			if err != nil {
				return nil, errors.New("control: system resolver owner unavailable")
			}
			uid, err := strconv.ParseUint(principal.Uid, 10, 32)
			if err != nil || uid == 0 || uint64(owner) != uid {
				return nil, errors.New("control: system resolver owner differs")
			}
			resolverUID = uint32(uid)
		}
	}
	return readOwnedDNSFile(path, resolverUID)
}

func readOwnedDNSFile(path string, resolverUID uint32) ([]byte, error) {
	invalid := errors.New("control: unsafe service DNS file")
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, invalid
		}
		uid, err := entryFileUID(info)
		resolvedOwner := resolverUID != 0 && uid == resolverUID && (current == path || current == "/run/systemd/resolve")
		if err != nil || uid != 0 && !resolvedOwner || current != path && !info.IsDir() {
			return nil, invalid
		}
		if current == path && (!info.Mode().IsRegular() || info.Size() > 65536) {
			return nil, invalid
		}
		if current == "/" {
			break
		}
	}
	return os.ReadFile(path)
}
