//go:build linux || darwin

package control

import (
	"errors"
	"os"
	"syscall"
)

func entryFileUID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("control: entry file ownership unavailable")
	}
	return stat.Uid, nil
}
