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

// PairingObservation refuses unresolved maintenance without replaying recovery
// or changing a counter. The caller holds the stopped manager's directory lease.
func (r *NativeRuntime) PairingObservation(ctx context.Context) (Observation, error) {
	for _, name := range []string{"transport-prepared.json", "commit-pending.json"} {
		if _, err := os.Lstat(filepath.Join(r.Directory, name)); !errors.Is(err, os.ErrNotExist) {
			return Observation{}, errors.New("control: finish runtime maintenance before pairing")
		}
	}
	if err := checkPairingLegacyState(ctx, r); err != nil {
		return Observation{}, err
	}
	return r.Inspect(ctx)
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
	want := "LoadCredential=configuration.json:" + strconv.Quote(filepath.Join(directory, "config.json"))
	if err != nil || !strings.Contains("\n"+string(raw), "\n"+want+"\n") {
		return errors.New("control: companion worker does not consume the selected state directory")
	}
	state, err := inspectNativeEntry(ctx, d)
	if err != nil || state.Active || state.PID != 0 || state.ControlPID != 0 {
		return errors.New("control: additional role worker must be stopped before pairing")
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
