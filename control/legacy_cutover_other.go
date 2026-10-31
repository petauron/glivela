//go:build !linux

package control

import (
	"context"
	"errors"
)

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
