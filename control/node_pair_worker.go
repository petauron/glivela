package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CheckPairingSource inspects the retained local runtime without replaying
// recovery, warming up routes or claiming a business-ready receipt. Entry
// startup acceptance was owned by the STOPPED manager and must be established
// again on normal startup; a new offline driver's monitors are intentionally empty.
func (r *NativeRuntime) CheckPairingSource(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, err := r.pairingCurrent(ctx)
	if err != nil {
		return err
	}
	switch driver := r.Driver.(type) {
	case *NativeEntryDriver:
		if err := driver.readyProcess(ctx, current); err != nil {
			return err
		}
		policy, err := driver.policy(current)
		if err != nil {
			return err
		}
		return policy.Verify(ctx)
	case SystemdDriver:
		if err := driver.verifyLoadedService(ctx); err != nil {
			return err
		}
		process, err := inspectNativeEntry(ctx, driver)
		if err != nil || !process.Active || process.PID <= 0 || process.ControlPID != 0 {
			return errors.New("control: original landing worker is not running")
		}
		if err := verifyNativeEntryProcess(driver, process, current); err != nil {
			return err
		}
		return driver.Healthy(ctx, current)
	default:
		return errors.New("control: concrete installed native role required for pairing")
	}
}

func (r *NativeRuntime) pairingCurrent(ctx context.Context) (Desired, error) {
	for _, name := range []string{"transport-prepared.json", "commit-pending.json"} {
		if _, err := os.Lstat(filepath.Join(r.Directory, name)); !errors.Is(err, os.ErrNotExist) {
			return Desired{}, errors.New("control: finish runtime maintenance before pairing")
		}
	}
	if err := checkPairingLegacyState(ctx, r); err != nil {
		return Desired{}, err
	}
	state, err := r.journal()
	if err != nil || state.Phase != "ready" || state.Retired || state.Current == nil {
		return Desired{}, errors.New("control: complete committed state required for pairing")
	}
	if err := r.verifyConfig(*state.Current); err != nil {
		return Desired{}, err
	}
	return state.Current.clone(), nil
}

// CheckPairingWorker checks a dormant, already-installed second role. It never
// stops an existing worker, replaces an installation or claims proxy readiness.
func (d SystemdDriver) CheckPairingWorker(ctx context.Context, directory string) error {
	if d.Role != "entry" && d.Role != "landing" || d.WorkerUID == 0 || d.WorkerGID == 0 {
		return errors.New("control: independent native role worker required")
	}
	if err := d.verifyLoadedService(ctx); err != nil {
		return err
	}
	if d.InitSystem != "" {
		return errors.New("control: staged role expansion currently requires systemd")
	}
	unit, err := d.installationNames()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(unit)
	if err != nil {
		return err
	}
	if err := pairingWorkerCredential(string(raw), directory); err != nil {
		return err
	}
	state, err := inspectNativeEntry(ctx, d)
	if err != nil || state.Active || state.PID != 0 || state.ControlPID != 0 {
		return errors.New("control: additional role worker must be stopped before pairing")
	}
	return nil
}

func pairingWorkerCredential(unit, directory string) error {
	count := 0
	for _, line := range strings.Split(unit, "\n") {
		value, ok := strings.CutPrefix(line, "LoadCredential=configuration.json:")
		if !ok {
			continue
		}
		count++
		if strings.HasPrefix(value, "\"") {
			var err error
			value, err = strconv.Unquote(value)
			if err != nil {
				return errors.New("control: ambiguous worker credential source")
			}
		}
		if strings.ContainsAny(value, "%$\x00\r\n") || value != filepath.Join(directory, "config.json") {
			return errors.New("control: companion worker does not consume the selected state directory")
		}
	}
	if count != 1 {
		return errors.New("control: exactly one owned worker configuration source required")
	}
	return nil
}

// CheckPairingDirectories accepts only state paths declared by the exact,
// root-owned installed manager. Root ownership of an arbitrary directory alone
// is not proof that it belongs to this application.
func CheckPairingDirectories(installation, service string, directories []string) error {
	if _, _, _, err := InstalledMaintenanceFiles(installation, service); err != nil {
		return err
	}
	raw, err := os.ReadFile(installation)
	var inventory nativeInstallationInventory
	if err != nil || json.Unmarshal(raw, &inventory) != nil || inventory.InitSystem != "" {
		return errors.New("control: staged role expansion currently requires systemd")
	}
	manager := inventory.Services[service]
	unit := filepath.Join("/etc/systemd/system", manager.Unit)
	if err := verifyExecutableFile(unit, manager.SHA256); err != nil {
		return err
	}
	raw, err = os.ReadFile(unit)
	if err != nil {
		return err
	}
	return pairingDeclaredDirectories(string(raw), directories)
}

func pairingDeclaredDirectories(unit string, directories []string) error {
	declared := map[string]bool{}
	for _, line := range strings.Split(unit, "\n") {
		if value, ok := strings.CutPrefix(line, "StateDirectory="); ok {
			for _, name := range strings.Fields(value) {
				if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.ContainsAny(name, "%$\\\"'):") || name == ".." || strings.HasPrefix(name, "../") {
					return errors.New("control: ambiguous installed state declaration")
				}
				declared[filepath.Join("/var/lib", name)] = true
			}
		}
	}
	for _, directory := range directories {
		if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !declared[directory] {
			return errors.New("control: paired directory is not declared by the installed manager")
		}
	}
	return nil
}
