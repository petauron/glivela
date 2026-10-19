package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/petauron/glivela/landing"
)

type legacyCutover struct {
	Version    int     `json:"version"`
	NodeID     string  `json:"nodeId"`
	Checkpoint string  `json:"checkpoint"`
	Binding    string  `json:"binding"`
	Phase      string  `json:"phase"`
	WasEnabled bool    `json:"wasEnabled"`
	Candidate  Desired `json:"candidate"`
}

// SwitchLegacyLanding is an offline first-cutover operation, not a health
// acceptance. The old Agent must already be stopped and persistently masked.
// The caller supplies the local immutable installation inventory, never remote
// command text. A directory lock excludes a simultaneously running node.
func SwitchLegacyLanding(ctx context.Context, directory, checkpoint, nodeID string, driver SystemdDriver) error {
	if os.Geteuid() != 0 {
		return errors.New("control: legacy cutover requires root")
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	r := &NativeRuntime{Directory: directory, Driver: driver}
	if _, err := readLegacyCutover(r); !errors.Is(err, os.ErrNotExist) {
		return errors.New("control: previous cutover must be inspected or recovered before another switch")
	}
	if _, err := r.journal(); !errors.Is(err, os.ErrNotExist) {
		return errors.New("control: first cutover requires an unused owned runtime")
	}
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return err
	}
	saved, program, err := loadLegacyBackup(checkpoint, nodeID, 0)
	if err != nil {
		return err
	}
	program.Close()
	current, err := SnapshotLegacyLanding(nodeID)
	if err != nil || !sameLegacyResources(saved, current) || saved.RecoveryProgram != current.RecoveryProgram {
		return errors.New("control: legacy backup no longer matches the installation")
	}
	plan, policy, err := saved.migrationPlan()
	if err != nil || plan.Revision == ^uint64(0) {
		return errors.New("control: legacy revision cannot advance")
	}
	plan.Revision++
	candidate, err := NewDesired(plan)
	if err != nil {
		return err
	}
	if driver.Interface != policy.Interface {
		return errors.New("control: migration must retain the private interface")
	}
	if _, err := driver.policy(candidate); err != nil {
		return err
	}
	for _, unit := range []string{"vastora-landing.service", "vastora-landing-firewall.service"} {
		if err := requireLegacyUnitLoaded(ctx, unit); err != nil {
			return err
		}
	}
	legacy := legacyFirewall(policy)
	if err := legacy.Verify(ctx); err != nil {
		return err
	}
	// Validate the bundled core before stopping the working old proxy.
	if err := replacePrivate(directory, "candidate.json", candidate.Config); err != nil {
		return err
	}
	if err := driver.Validate(ctx, candidate, filepath.Join(directory, "candidate.json")); err != nil {
		return err
	}
	// Verify the installed candidate unit without starting or stopping it.
	if err := driver.verifyLoadedService(ctx); err != nil {
		return err
	}
	enabled, err := legacyUnitEnabled(ctx)
	if err != nil {
		return err
	}
	state := legacyCutover{Version: 1, NodeID: nodeID, Checkpoint: checkpoint, Binding: driver.Binding(), Phase: "pending", WasEnabled: enabled, Candidate: candidate}
	if err := saveLegacyCutover(directory, state); err != nil {
		return err
	}
	if err := switchLegacyRuntime(ctx, r, state, legacy); err != nil {
		recovery, cancel := recoveryContext()
		defer cancel()
		if rollbackLegacyCutover(recovery, r, state, driver) != nil {
			return errors.New("control: first cutover failed; recovery required")
		}
		return errors.New("control: first cutover failed; legacy runtime restored, route verification required")
	}
	state.Phase = "awaiting-routes"
	if err := saveLegacyCutover(directory, state); err != nil {
		recovery, cancel := recoveryContext()
		defer cancel()
		if rollbackLegacyCutover(recovery, r, state, driver) != nil {
			return errors.New("control: cutover persistence failed; recovery required")
		}
		return errors.New("control: cutover persistence failed; legacy runtime restored")
	}
	return nil
}

func legacyFirewall(p legacyPolicy) landing.LegacyDanteFirewall {
	return landing.LegacyDanteFirewall{EgressIP: p.EgressIP, Revision: p.Revision, Address: p.Address, Sources: p.Sources, TCPOnlySources: p.TCPOnlySources, Interface: p.Interface, UID: p.UID}
}

func switchLegacyRuntime(ctx context.Context, r *NativeRuntime, state legacyCutover, legacy landing.LegacyDanteFirewall) error {
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return err
	}
	if err := legacySystemctl(ctx, "stop", "vastora-landing.service"); err != nil {
		return err
	}
	if err := requireLegacyProxyStopped(ctx); err != nil {
		return err
	}
	// Disable boot activation before withdrawing the old prerequisite. Exact
	// unit files and recovery backups remain untouched until route acceptance.
	if err := legacySystemctl(ctx, "disable", "vastora-landing.service"); err != nil {
		return err
	}
	if err := legacySystemctl(ctx, "stop", "vastora-landing-firewall.service"); err != nil {
		return err
	}
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return err
	}
	if err := legacy.Remove(ctx); err != nil {
		return err
	}
	return r.Apply(ctx, state.Candidate)
}

func saveLegacyCutover(directory string, state legacyCutover) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return replacePrivate(directory, "legacy-cutover.json", raw)
}

func readLegacyCutover(r *NativeRuntime) (legacyCutover, error) {
	var state legacyCutover
	path := filepath.Join(r.Directory, "legacy-cutover.json")
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 3*maxMessage {
		return state, errors.New("control: unsafe cutover journal")
	}
	raw, err := os.ReadFile(path)
	if err != nil || decode(strings.NewReader(string(raw)), &state) != nil || state.Version != 1 || state.NodeID == "" || state.Binding != r.Driver.Binding() || state.Candidate.Validate() != nil || state.Candidate.Landing == nil || !filepath.IsAbs(state.Checkpoint) {
		return state, errors.New("control: invalid cutover journal")
	}
	if state.Phase != "pending" && state.Phase != "awaiting-routes" && state.Phase != "rolled-back" {
		return state, errors.New("control: unknown cutover phase")
	}
	return state, nil
}

func checkLegacyCutoverApply(r *NativeRuntime, desired Desired) error {
	state, err := readLegacyCutover(r)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Phase == "rolled-back" || desired.Revision != state.Candidate.Revision || desired.ConfigSHA256 != state.Candidate.ConfigSHA256 {
		return errors.New("control: first cutover awaits acceptance or explicit recovery; later revisions refused")
	}
	return nil
}

func rollbackLegacyCutover(ctx context.Context, r *NativeRuntime, state legacyCutover, driver SystemdDriver) error {
	if err := restoreLegacyLandingRuntime(ctx, state.Checkpoint, state.NodeID, state.Candidate, driver); err != nil {
		return err
	}
	if state.WasEnabled {
		if err := legacySystemctl(ctx, "enable", "vastora-landing.service"); err != nil {
			return err
		}
	}
	state.Phase = "rolled-back"
	return saveLegacyCutover(r.Directory, state)
}

// RecoverLegacyCutover runs before normal node startup recovery. Interrupted
// first switches restore Dante; a rolled-back migration blocks automatic
// reapplication so polling cannot repeatedly interrupt the restored service.
// A locally ready Xray remains awaiting entry-side route acceptance.
func RecoverLegacyCutover(ctx context.Context, r *NativeRuntime) error {
	state, err := readLegacyCutover(r)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	driver, ok := r.Driver.(SystemdDriver)
	if !ok {
		return errors.New("control: cutover requires the native installed driver")
	}
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return err
	}
	if state.Phase == "pending" {
		if err := rollbackLegacyCutover(ctx, r, state, driver); err != nil {
			return errors.New("control: interrupted cutover recovery failed")
		}
		return errors.New("control: interrupted cutover restored legacy runtime; explicit investigation required")
	}
	if state.Phase == "rolled-back" {
		return errors.New("control: legacy runtime restored; automatic cutover retry refused")
	}
	if err := requireLegacyProxyStopped(ctx); err != nil {
		return err
	}
	return nil
}

func legacySystemctl(ctx context.Context, action, unit string) error {
	if unit != "vastora-landing.service" && unit != "vastora-landing-firewall.service" {
		return errors.New("control: unknown legacy service")
	}
	if action != "stop" && action != "disable" && action != "enable" {
		return errors.New("control: unknown legacy operation")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if exec.CommandContext(bounded, "/usr/bin/systemctl", action, unit).Run() != nil {
		return errors.New("control: legacy service operation failed")
	}
	return nil
}

func legacyUnitEnabled(ctx context.Context) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", "vastora-landing.service", "--property=UnitFileState", "--value").Output()
	if err != nil {
		return false, errors.New("control: legacy boot state unavailable")
	}
	switch strings.TrimSpace(string(raw)) {
	case "enabled":
		return true, nil
	case "disabled":
		return false, nil
	default:
		return false, errors.New("control: unsupported legacy boot state")
	}
}

func requireLegacyProxyStopped(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", "vastora-landing.service", "--property=ActiveState,SubState,MainPID,ControlPID").Output()
	if err != nil || !legacyProxyStopped(string(raw)) {
		return errors.New("control: legacy proxy is not confirmed stopped")
	}
	return nil
}

func legacyProxyStopped(raw string) bool {
	want := map[string]string{"ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		expected, known := want[key]
		if !ok || !known || seen[key] || value != expected {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}
