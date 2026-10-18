package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistributionResolvesPinnedCoreAndRejectsChangedMetadata(t *testing.T) {
	for _, failure := range []string{"", "architecture", "version", "digest", "unknown", "symlink", "writable"} {
		t.Run(failure, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			binary := []byte("synthetic executable fixture")
			hash := sha256.Sum256(binary)
			metadata := distributionMetadata{Version: "0.1.0-alpha.1", Commit: strings.Repeat("a", 40), OS: "linux", Architecture: "amd64"}
			metadata.Xray.Version = "26.7.28"
			metadata.Xray.SHA256 = hex.EncodeToString(hash[:])
			metadata.Xray.SourceArchiveSHA256 = strings.Repeat("b", 64)
			if failure == "architecture" {
				metadata.Architecture = "arm64"
			}
			if failure == "version" {
				metadata.Xray.Version = "latest"
			}
			if failure == "digest" {
				binary = []byte("replaced")
			}
			raw, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "unknown" {
				raw = append([]byte(`{"override":true,`), raw[1:]...)
			}
			if err := os.WriteFile(filepath.Join(directory, "runtime.json"), raw, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "xray"), binary, 0755); err != nil {
				t.Fatal(err)
			}
			if failure == "writable" {
				if err := os.Chmod(filepath.Join(directory, "runtime.json"), 0666); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "symlink" {
				link := filepath.Join(directory, "linked")
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				directory = link
			}
			d, err := (SystemdDriver{Distribution: directory}).resolveDistribution("linux", "amd64")
			if failure == "" {
				if err != nil || d.Binary != filepath.Join(directory, "xray") || d.BinarySHA256 != metadata.Xray.SHA256 {
					t.Fatal("verified distribution rejected", err)
				}
			} else if err == nil {
				t.Fatal("invalid distribution accepted")
			}
		})
	}
}
