package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

// restoreLegacyLandingRuntime is the local part of failed-cutover recovery. The
// caller must keep the old writer fenced. It stops the owned candidate before
// restoring old rules and Dante. It does not declare routes healthy or release
// the migration fence: entry-side verification and authority transfer are separate.
func restoreLegacyLandingRuntime(ctx context.Context, checkpoint, nodeID string, candidate Desired, driver SystemdDriver) error {
	if os.Geteuid() != 0 {
		return errors.New("control: legacy recovery requires root")
	}
	if candidate.Validate() != nil {
		return errors.New("control: invalid replacement identity")
	}
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return err
	}
	saved, program, err := loadLegacyBackup(checkpoint, nodeID, 0)
	if err != nil {
		return err
	}
	defer program.Close()
	current, err := SnapshotLegacyLanding(nodeID)
	if err != nil || !sameLegacyResources(saved, current) {
		return errors.New("control: legacy resources changed; recovery refused")
	}
	for _, unit := range []string{"vastora-landing-firewall.service", "vastora-landing.service"} {
		if err := requireLegacyUnitLoaded(ctx, unit); err != nil {
			return err
		}
	}
	firewallActive := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "vastora-landing-firewall.service").Run() == nil
	// If systemd must start the old prerequisite, its on-disk executable must
	// still be the snapshotted version. Never execute a newer Agent as rollback.
	if !firewallActive && current.RecoveryProgram != saved.RecoveryProgram {
		return errors.New("control: inactive legacy prerequisite changed; recovery refused")
	}
	// Stop verifies the exact installed unit/binary identity and removes only
	// this candidate's owned firewall table. Failure must not enable the old
	// rules while the replacement could still be forwarding traffic.
	if err := driver.Stop(ctx, candidate); err != nil {
		return errors.New("control: replacement could not be stopped; recovery refused")
	}
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Execute the verified open inode, not the old mutable installation path.
	// ExtraFiles gives this fd number 3 in the child on Linux. The retained
	// program reads the unchanged, verified legacy ownership journal itself.
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "agent", "landing-firewall")
	command.ExtraFiles = []*os.File{program}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if command.Run() != nil {
		return errors.New("control: retained firewall recovery failed")
	}
	if !firewallActive {
		if exec.CommandContext(bounded, "/usr/bin/systemctl", "start", "vastora-landing-firewall.service").Run() != nil {
			return errors.New("control: legacy firewall prerequisite failed")
		}
	}
	if err := requireLegacyWriterStopped(bounded); err != nil {
		return err
	}
	if exec.CommandContext(bounded, "/usr/bin/systemctl", "start", "vastora-landing.service").Run() != nil {
		return errors.New("control: legacy proxy restart failed")
	}
	for _, unit := range []string{"vastora-landing-firewall.service", "vastora-landing.service"} {
		if exec.CommandContext(bounded, "/usr/bin/systemctl", "is-active", "--quiet", unit).Run() != nil {
			return errors.New("control: legacy runtime not active after recovery")
		}
	}
	plan, policy, err := saved.migrationPlan()
	if err != nil {
		return err
	}
	ready, cancelReady := context.WithTimeout(ctx, 5*time.Second)
	defer cancelReady()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if verifyOwnedListener(plan.Address, 1080, policy.UID) == nil {
			return nil
		}
		select {
		case <-ready.Done():
			return errors.New("control: legacy runtime did not restore its owned listener")
		case <-ticker.C:
		}
	}
}

func requireLegacyUnitLoaded(ctx context.Context, unit string) error {
	if unit != "vastora-landing-firewall.service" && unit != "vastora-landing.service" {
		return errors.New("control: unknown legacy unit")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", unit, "--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload").Output()
	if err != nil || !legacyUnitLoaded(string(raw), unit) {
		return errors.New("control: legacy loaded service differs from checkpoint")
	}
	return nil
}

func legacyUnitLoaded(raw, unit string) bool {
	want := map[string]string{"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/" + unit, "DropInPaths": "", "NeedDaemonReload": "no"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		expected, known := want[key]
		if !ok || !known || seen[key] || value != expected {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}

// Initial authority transfer requires an explicit maintenance fence. Merely
// pausing task claims is insufficient: the old Agent has autonomous account
// and subscription writers. This check does not stop or mask any host service.
func requireLegacyWriterStopped(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", "vastora-agent.service", "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,UnitFileState").Output()
	if err != nil || !legacyWriterStopped(string(raw)) {
		return errors.New("control: legacy writer must be stopped and persistently masked before recovery")
	}
	return nil
}

func legacyWriterStopped(raw string) bool {
	want := map[string]string{"LoadState": "masked", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "UnitFileState": "masked"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		expected, known := want[key]
		if !ok || !known || seen[key] || expected != value {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}

func sameLegacyResources(saved, current LegacyLandingSnapshot) bool {
	return saved.NodeID == current.NodeID && saved.Revision == current.Revision && bytes.Equal(saved.Journal, current.Journal) && reflect.DeepEqual(saved.Files, current.Files)
}
