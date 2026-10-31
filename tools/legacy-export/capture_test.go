package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stoppedContainerFixture(data string) oldCenterContainer {
	c := oldCenterContainer{ID: strings.Repeat("a", 64), Labels: map[string]string{"io.vastora.managed": "true", "io.vastora.component": "center"}, Entrypoint: []string{"/usr/local/bin/vastora"}, Command: []string{"center", "serve", "--data-dir", "/var/lib/vastora"}, Restart: "no"}
	c.State.Status, c.State.StartedAt, c.State.FinishedAt = "exited", "2026-10-19T01:00:00Z", "2026-10-19T02:00:00Z"
	c.Mounts = []struct {
		Source, Destination string
		RW                  bool
	}{{data, "/var/lib/vastora", true}}
	return c
}

func TestFinalCaptureRequiresActualStoppedWriterAndExactOwnership(t *testing.T) {
	for _, fault := range []string{"running", "restarting", "pid", "restart-policy", "created", "wrong-command", "duplicate-data-flag", "wrong-data-flag", "wrong-entrypoint", "wrong-label", "wrong-mount", "parent-mount", "second-writer", "stopped-second-autorestart", "missing", "duplicate", "not-started"} {
		t.Run(fault, func(t *testing.T) {
			c := stoppedContainerFixture("/private/example/source")
			id := c.ID
			list := []oldCenterContainer{c}
			switch fault {
			case "running":
				list[0].State.Running = true
			case "restarting":
				list[0].State.Restarting = true
			case "pid":
				list[0].State.Pid = 42
			case "restart-policy":
				list[0].Restart = "unless-stopped"
			case "created":
				list[0].State.Status = "created"
			case "wrong-command":
				list[0].Command[0] = "agent"
			case "duplicate-data-flag":
				list[0].Command = append(list[0].Command, "--data-dir", "/var/lib/vastora")
			case "wrong-data-flag":
				list[0].Command = []string{"center", "serve", "--data-dir=/other", "ignored"}
			case "wrong-entrypoint":
				list[0].Entrypoint = []string{"/unowned/program"}
			case "wrong-label":
				list[0].Labels["io.vastora.component"] = "deployer"
			case "wrong-mount":
				list[0].Mounts[0].Destination = "/other"
			case "parent-mount":
				list[0].Mounts[0].Source = "/private/example"
			case "second-writer", "stopped-second-autorestart":
				second := stoppedContainerFixture("/private/example/source")
				second.ID = strings.Repeat("b", 64)
				second.State.Running = fault == "second-writer"
				if fault == "stopped-second-autorestart" {
					second.Restart = "always"
				}
				list = append(list, second)
			case "missing":
				list = nil
			case "duplicate":
				list = append(list, c)
			case "not-started":
				list[0].State.StartedAt = "0001-01-01T00:00:00Z"
			}
			if _, err := stoppedCenter(list, id, "/private/example/source"); err == nil {
				t.Fatal("unconfirmed writer isolation accepted")
			}
		})
	}
	c := stoppedContainerFixture("/private/example/source")
	stopped := stoppedContainerFixture("/private/example/source")
	stopped.ID = strings.Repeat("b", 64)
	if _, err := stoppedCenter([]oldCenterContainer{c, stopped}, c.ID, "/private/example/source"); err != nil {
		t.Fatal(err)
	}
}

func TestFinalCaptureRetainsExactBytesAndDoesNotOverwrite(t *testing.T) {
	path, key, db := fixture(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data := filepath.Dir(path)
	if err := os.Rename(path, filepath.Join(data, "center.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "center.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(filepath.Dir(data), filepath.Base(data)+"-captured")
	t.Cleanup(func() { os.RemoveAll(backup) })
	c := stoppedContainerFixture(data)
	inspections := 0
	inspect := func(context.Context) ([]oldCenterContainer, error) {
		inspections++
		return []oldCenterContainer{c}, nil
	}
	if err := captureFinal(context.Background(), data, backup, c.ID, inspect); err != nil {
		t.Fatal(err)
	}
	if inspections != 2 {
		t.Fatal("writer was not rechecked")
	}
	for _, name := range []string{"center.db", "center.key"} {
		original, err := os.ReadFile(filepath.Join(data, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := privateFile(filepath.Join(backup, name), maxSnapshotBytes)
		if err != nil || !bytes.Equal(original, got) {
			t.Fatal("final backup differs from frozen source", err)
		}
	}
	var receipt finalCapture
	raw, err := privateFile(filepath.Join(backup, "capture.json"), 4096)
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("capture completion missing", err)
	}
	database, err := os.ReadFile(filepath.Join(data, "center.db"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(database)
	if receipt.Version != 1 || receipt.ContainerID != c.ID || receipt.DatabaseSHA256 != hex.EncodeToString(sum[:]) || receipt.StoppedAt != c.State.FinishedAt {
		t.Fatal("capture identity changed")
	}
	if captureFinal(context.Background(), data, backup, c.ID, inspect) == nil {
		t.Fatal("existing backup was overwritten")
	}
	transfer := filepath.Join(data, "transfer.key")
	if err := os.WriteFile(transfer, bytes.Repeat([]byte{9}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := export(context.Background(), filepath.Join(backup, "center.db"), filepath.Join(backup, "center.key"), transfer, "snapshot-example", filepath.Join(backup, "final.sealed")); err != nil {
		t.Fatal("captured database did not pass real offline SQLite export", err)
	}
}

func TestFinalCaptureChangedWriterOrDataNeverGetsCompletion(t *testing.T) {
	for _, fault := range []string{"writer-restarted", "database-changed", "key-changed", "sidecar", "existing-output"} {
		t.Run(fault, func(t *testing.T) {
			data, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for name, raw := range map[string][]byte{"center.db": []byte("synthetic-source"), "center.key": bytes.Repeat([]byte{3}, 32)} {
				if err := os.WriteFile(filepath.Join(data, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			backup := filepath.Join(filepath.Dir(data), filepath.Base(data)+"-failed")
			t.Cleanup(func() { os.RemoveAll(backup) })
			if fault == "existing-output" {
				if err := os.Mkdir(backup, 0700); err != nil {
					t.Fatal(err)
				}
			}
			c := stoppedContainerFixture(data)
			calls := 0
			inspect := func(context.Context) ([]oldCenterContainer, error) {
				calls++
				if calls == 1 {
					switch fault {
					case "sidecar":
						if err := os.WriteFile(filepath.Join(data, "center.db-wal"), []byte("uncheckpointed"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					switch fault {
					case "writer-restarted":
						c.State.Running = true
					case "database-changed":
						if err := os.WriteFile(filepath.Join(data, "center.db"), []byte("changed-source"), 0600); err != nil {
							t.Fatal(err)
						}
					case "key-changed":
						if err := os.WriteFile(filepath.Join(data, "center.key"), bytes.Repeat([]byte{4}, 32), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				return []oldCenterContainer{c}, nil
			}
			if captureFinal(context.Background(), data, backup, c.ID, inspect) == nil {
				t.Fatal("changed capture accepted")
			}
			if _, err := os.Stat(filepath.Join(backup, "capture.json")); !os.IsNotExist(err) {
				t.Fatal("failed capture emitted completion marker")
			}
		})
	}
}
