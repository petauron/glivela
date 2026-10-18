package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"time"
)

// restoreLegacyLandingFirewall is only a step of failed-cutover recovery. The
// caller must first stop the candidate and keep the old writer fenced. It does
// not start Dante, declare routes healthy, or release the migration fence.
func restoreLegacyLandingFirewall(ctx context.Context, checkpoint, nodeID string) error {
	if os.Geteuid() != 0 {
		return errors.New("control: legacy recovery requires root")
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
	return nil
}

func sameLegacyResources(saved, current LegacyLandingSnapshot) bool {
	return saved.NodeID == current.NodeID && saved.Revision == current.Revision && bytes.Equal(saved.Journal, current.Journal) && reflect.DeepEqual(saved.Files, current.Files)
}
