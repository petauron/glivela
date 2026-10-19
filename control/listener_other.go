//go:build !linux

package control

import "errors"

func verifyOwnedListener(string, uint16, uint32) error {
	return errors.New("control: native Xray listener inspection requires Linux")
}
