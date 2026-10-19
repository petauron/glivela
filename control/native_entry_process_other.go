//go:build !linux

package control

import (
	"context"
	"errors"
)

func inspectNativeEntry(context.Context, SystemdDriver) (nativeEntryProcess, error) {
	return nativeEntryProcess{}, errors.New("control: native entry requires Linux")
}
func verifyNativeEntryProcess(SystemdDriver, nativeEntryProcess, Desired) error {
	return errors.New("control: native entry requires Linux")
}
func (*NativeEntryDriver) traffic(context.Context, Desired) (*EntryTraffic, error) {
	return nil, errors.New("control: native entry requires Linux")
}
