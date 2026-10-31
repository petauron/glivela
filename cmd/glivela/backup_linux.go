package main

import (
	"errors"
	"github.com/petauron/glivela/control"
	"os"
)

func backupLegacyLanding(directory, nodeID string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("legacy backup requires root")
	}
	return control.BackupLegacyLanding(directory, nodeID)
}
