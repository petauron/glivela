//go:build !linux

package control

import (
	"context"
	"errors"
)

func (d SystemdDriver) openRCService(context.Context, string) error {
	return errors.New("control: OpenRC requires Linux")
}
func (d SystemdDriver) verifyOpenRCService() error {
	return errors.New("control: OpenRC requires Linux")
}
