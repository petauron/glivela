package control

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	invalid := errors.New("control: unsafe service DNS file")
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, invalid
		}
		uid, err := entryFileUID(info)
		if err != nil || uid != 0 || current != path && !info.IsDir() {
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
