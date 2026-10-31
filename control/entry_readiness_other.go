//go:build !linux

package control

import "errors"

func verifyReadinessListener(pid, port int) error {
	return errors.New("control: readiness client ownership requires Linux")
}
