//go:build linux

package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenRCKernelGenerationChangesOnPIDReuse(t *testing.T) {
	root := t.TempDir()
	put := func(path, value string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	put("proc/sys/kernel/random/boot_id", "11111111-1111-4111-8111-111111111111\n")
	put("proc/stat", "btime 1000\n")
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[19] = "100"
	put("proc/42/stat", "42 (worker name) "+strings.Join(fields, " "))
	first, err := openRCProcessGeneration(root, 42, time.Unix(2000, 0))
	if err != nil {
		t.Fatal(err)
	}
	fields[19] = "200"
	put("proc/42/stat", "42 (worker name) "+strings.Join(fields, " "))
	second, err := openRCProcessGeneration(root, 42, time.Unix(2000, 0))
	if err != nil || first.Invocation == second.Invocation || first.StartedAt == second.StartedAt {
		t.Fatal("PID reuse accepted as same worker", err)
	}
	fields[0] = "Z"
	put("proc/42/stat", "42 (worker name) "+strings.Join(fields, " "))
	if _, err := openRCProcessGeneration(root, 42, time.Unix(2000, 0)); err == nil {
		t.Fatal("accepted zombie")
	}
}
