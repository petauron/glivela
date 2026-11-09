//go:build !linux

package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

func checkPairingLegacyState(_ context.Context, r *NativeRuntime) error {
	if _, err := os.Lstat(filepath.Join(r.Directory, "legacy-cutover.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("control: legacy pairing verification requires Linux")
	}
	return nil
}

// Legacy Dante native handover is Linux-only. Other platforms have no old
// host service to recover and cannot execute the switch command.
func RecoverLegacyCutover(context.Context, *NativeRuntime) error { return nil }

func checkLegacyCutoverApply(*NativeRuntime, Desired) error { return nil }

func SwitchLegacyLanding(context.Context, string, string, string, SystemdDriver) error {
	return errors.New("control: legacy cutover requires Linux")
}

func CompleteLegacyLanding(context.Context, string, string, SystemdDriver, *Client) error {
	return errors.New("control: legacy cutover requires Linux")
}
