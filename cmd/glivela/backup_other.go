//go:build !linux

package main

import "errors"

func backupLegacyLanding(directory, nodeID string) (string, error) {
	return "", errors.New("legacy landing backup requires Linux")
}
