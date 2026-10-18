//go:build !linux && !darwin

package control

import "errors"

func LockDirectory(string) (func(), error) {
	return nil, errors.New("control: unsupported state locking platform")
}
