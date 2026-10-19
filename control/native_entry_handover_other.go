//go:build !linux

package control

import (
	"context"
	"errors"
)

func StageNativeEntryHandover(context.Context, string, *NativeEntryDriver, Desired) error {
	return errors.New("control: native entry handover requires Linux")
}
