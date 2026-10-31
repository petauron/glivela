//go:build !linux && !darwin

package control

import (
	"errors"
	"os"
)

func entryFileUID(os.FileInfo) (uint32, error) {
	return 0, errors.New("control: entry file ownership unsupported")
}
