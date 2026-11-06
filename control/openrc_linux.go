//go:build linux

package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// OpenRC remains a local installation adapter. Neither service identifiers,
// shell fragments nor arbitrary commands are accepted from desired messages.
func (d SystemdDriver) openRCService(ctx context.Context, action string) error {
	switch action {
	case "start", "stop", "restart":
	case "is-active":
		action = "status"
	default:
		return errors.New("control: unsupported OpenRC service action")
	}
	name := strings.TrimSuffix(d.Unit, ".service")
	if exec.CommandContext(ctx, "/sbin/rc-service", name, action).Run() != nil {
		return errors.New("control: Xray OpenRC service operation failed")
	}
	return nil
}
func (d SystemdDriver) verifyOpenRCService() error {
	unit, err := d.installationNames()
	if err != nil {
		return err
	}
	if err := verifyExecutableFile(unit, d.UnitSHA256); err != nil {
		return err
	}
	// OpenRC's per-service conf.d could override command/user/capabilities after
	// the owned init script is read. There is no general override escape hatch.
	name := strings.TrimSuffix(d.Unit, ".service")
	for _, path := range []string{filepath.Join("/etc/conf.d", name), filepath.Join("/etc/conf.d", name+".default")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("control: unowned OpenRC service override")
		}
	}
	return nil
}
func inspectOpenRCEntry(ctx context.Context, d SystemdDriver) (nativeEntryProcess, error) {
	var result nativeEntryProcess
	if err := d.verifyOpenRCService(); err != nil {
		return result, err
	}
	raw, err := nativeEntryCommand(ctx, "/sbin/rc-service", strings.TrimSuffix(d.Unit, ".service"), "vastora_pid")
	if err != nil || len(raw) > 64 {
		return result, errors.New("control: OpenRC supervised process unavailable")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 0 {
		return result, errors.New("control: invalid OpenRC supervised PID")
	}
	if pid == 0 {
		return result, nil
	}
	if err := d.openRCService(ctx, "is-active"); err != nil {
		return result, err
	}
	return openRCProcessGeneration("", pid, time.Now())
}
func openRCProcessGeneration(root string, pid int, now time.Time) (nativeEntryProcess, error) {
	var result nativeEntryProcess
	if pid <= 1 {
		return result, errors.New("control: invalid OpenRC worker PID")
	}
	raw, err := os.ReadFile(filepath.Join(root, "/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return result, err
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return result, errors.New("control: invalid kernel process evidence")
	}
	fields := strings.Fields(string(raw)[end+2:])
	if len(fields) < 20 || fields[0] == "Z" {
		return result, errors.New("control: OpenRC worker is not running")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 || ticks > uint64((1<<63-1)/int64(10*time.Millisecond)) {
		return result, errors.New("control: invalid kernel process generation")
	}
	boot, err := os.ReadFile(filepath.Join(root, "/proc/sys/kernel/random/boot_id"))
	if err != nil {
		return result, err
	}
	bootID := strings.TrimSpace(string(boot))
	if len(bootID) != 36 {
		return result, errors.New("control: invalid kernel boot identity")
	}
	raw, err = os.ReadFile(filepath.Join(root, "/proc/stat"))
	if err != nil {
		return result, err
	}
	var bootTime int64
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "btime ") {
			bootTime, err = strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
			if err != nil {
				return result, err
			}
		}
	}
	if bootTime <= 0 {
		return result, errors.New("control: kernel boot time unavailable")
	}
	// Supported Linux amd64/arm64 expose USER_HZ=100 in procfs, independent of
	// the kernel scheduler's CONFIG_HZ setting.
	started := time.Unix(bootTime, 0).Add(time.Duration(ticks) * 10 * time.Millisecond)
	if started.After(now) {
		return result, errors.New("control: kernel process start time is in the future")
	}
	digest := sha256.Sum256([]byte(bootID + ":" + strconv.Itoa(pid) + ":" + fields[19]))
	return nativeEntryProcess{PID: pid, Active: true, Invocation: hex.EncodeToString(digest[:16]), StartedAt: started.UTC().Format(time.RFC3339Nano)}, nil
}
