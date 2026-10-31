package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestBackupLandingCommand(t *testing.T) {
	var output bytes.Buffer
	calls := 0
	backup := func(directory, node string) (string, error) {
		calls++
		if directory != "/private-recovery" || node != "node-example" {
			t.Fatal("wrong backup target")
		}
		return "/private-recovery/checkpoint/snapshot.json", nil
	}
	if err := backupLandingCommand([]string{"-node-id", "node-example", "-directory", "/private-recovery"}, &output, backup); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if json.Unmarshal(output.Bytes(), &result) != nil || result["status"] != "backup-only" || result["checkpoint"] != "/private-recovery/checkpoint/snapshot.json" || calls != 1 {
		t.Fatal("backup result does not distinguish preparation from migration")
	}
	for _, args := range [][]string{
		nil, {"-node-id", "node-example"}, {"-node-id", "node-example", "-directory", "relative"},
		{"-node-id", "node-example", "-directory", "/"},
		{"-node-id", "node-example", "-directory", "/private-recovery", "extra"},
		{"-node-id", "node-example", "-directory", "/private-recovery", "-config", "/other"},
	} {
		output.Reset()
		if backupLandingCommand(args, &output, backup) == nil || output.Len() != 0 || calls != 1 {
			t.Fatal("invalid command performed backup")
		}
	}
	output.Reset()
	if backupLandingCommand([]string{"-node-id", "node-example", "-directory", "/private-recovery"}, &output, func(string, string) (string, error) { return "", errors.New("private details") }) == nil || output.Len() != 0 {
		t.Fatal("failed backup reported success")
	}
}
