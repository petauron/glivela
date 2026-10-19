//go:build linux

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func nativeEntryCommand(ctx context.Context, binary string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	command.WaitDelay = time.Second
	var output entryCommandOutput
	command.Stdout = &output
	if command.Run() != nil {
		return nil, errors.New("control: native entry command unavailable")
	}
	return output.Bytes(), nil
}

func inspectNativeEntry(ctx context.Context, driver SystemdDriver) (nativeEntryProcess, error) {
	var result nativeEntryProcess
	if _, err := driver.installationNames(); err != nil {
		return result, err
	}
	raw, err := nativeEntryCommand(ctx, "/usr/bin/systemctl", "show", driver.Unit, "--property=ActiveState,SubState,MainPID,ControlPID,InvocationID,ExecMainStartTimestamp")
	if err != nil {
		return result, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return result, errors.New("control: invalid native entry process evidence")
		}
		if _, exists := values[key]; exists {
			return result, errors.New("control: duplicate native entry process evidence")
		}
		values[key] = value
	}
	for _, key := range []string{"ActiveState", "SubState", "MainPID", "ControlPID", "InvocationID", "ExecMainStartTimestamp"} {
		if _, ok := values[key]; !ok {
			return result, errors.New("control: incomplete native entry process evidence")
		}
	}
	if len(values) != 6 {
		return result, errors.New("control: unexpected native entry process evidence")
	}
	result.PID, err = strconv.Atoi(values["MainPID"])
	if err != nil || result.PID < 0 {
		return result, errors.New("control: invalid native entry PID")
	}
	result.ControlPID, err = strconv.Atoi(values["ControlPID"])
	if err != nil || result.ControlPID < 0 {
		return result, errors.New("control: invalid native entry control PID")
	}
	result.Active = values["ActiveState"] != "inactive" && values["ActiveState"] != "failed"
	if !result.Active {
		return result, nil
	}
	if values["ActiveState"] != "active" || values["SubState"] != "running" {
		return result, errors.New("control: native entry is transitioning")
	}
	id, err := hex.DecodeString(values["InvocationID"])
	started, timeErr := time.Parse("Mon 2006-01-02 15:04:05 MST", values["ExecMainStartTimestamp"])
	if err != nil || len(id) != 16 || timeErr != nil || started.IsZero() || started.After(time.Now()) {
		return result, errors.New("control: invalid native entry generation")
	}
	result.Invocation = values["InvocationID"]
	result.StartedAt = started.UTC().Format(time.RFC3339Nano)
	return result, nil
}

func verifyNativeEntryProcess(driver SystemdDriver, state nativeEntryProcess, desired Desired) error {
	root := filepath.Join("/proc", strconv.Itoa(state.PID))
	executable, err := os.Stat(filepath.Join(root, "exe"))
	if err != nil {
		return errors.New("control: native entry executable unavailable")
	}
	installed, err := os.Stat(driver.Binary)
	if err != nil || !os.SameFile(executable, installed) {
		return errors.New("control: native entry executes another artifact")
	}
	config := filepath.Join("/run", strings.TrimSuffix(driver.Unit, ".service"), "configuration")
	raw, err := os.ReadFile(filepath.Join(root, "cmdline"))
	if err != nil || len(raw) > 64<<10 || !slices.Equal(strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00"), []string{driver.Binary, "run", "-format", "json", "-config", config}) {
		return errors.New("control: native entry arguments differ from installed worker")
	}
	if err := verifyEntryConfigFile(config, desired.Config); err != nil {
		return err
	}
	// The signed worker declaration may grant only CAP_NET_BIND_SERVICE;
	// that ceiling stays valid when HY2 is later disabled in business config.
	return verifyEntryProcessResources(root, driver.WorkerUID, driver.WorkerGID, desired, true)
}

func (d *NativeEntryDriver) traffic(ctx context.Context, desired Desired) (*EntryTraffic, error) {
	if err := d.readyProcess(ctx, desired); err != nil {
		return nil, err
	}
	before, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil {
		return nil, err
	}
	if err := verifyExecutableFile(d.Binary, d.BinarySHA256); err != nil {
		return nil, err
	}
	raw, err := nativeEntryCommand(ctx, d.Binary, "api", "statsquery", "--server=127.0.0.1:10085")
	if err != nil {
		return nil, err
	}
	sample, err := parseEntryTraffic(raw, desired, before.StartedAt)
	if err != nil {
		return nil, err
	}
	after, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || before != after {
		return nil, errors.New("control: native entry restarted during traffic sampling")
	}
	return sample, nil
}
