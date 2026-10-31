package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationResolvesOnlyDeclaredService(t *testing.T) {
	for _, failure := range []string{"", "missing", "version", "digest", "root", "unit", "unknown", "trailing", "writable", "symlink"} {
		t.Run(failure, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "installation.json")
			raw := `{"version":1,"services":{"worker":{"unit":"example-worker.service","user":"example-worker","sha256":"` + strings.Repeat("a", 64) + `"}}}`
			switch failure {
			case "missing":
				raw = strings.ReplaceAll(raw, `"worker":`, `"other":`)
			case "version":
				raw = strings.Replace(raw, `"version":1`, `"version":2`, 1)
			case "digest":
				raw = strings.ReplaceAll(raw, strings.Repeat("a", 64), "invalid")
			case "root":
				raw = strings.Replace(raw, `"user":"example-worker"`, `"user":"root"`, 1)
			case "unit":
				raw = strings.ReplaceAll(raw, "example-worker.service", "../../sshd.service")
			case "unknown":
				raw = strings.Replace(raw, `"version":1`, `"version":1,"command":"override"`, 1)
			case "trailing":
				raw += `{}`
			}
			if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
				t.Fatal(err)
			}
			if failure == "writable" {
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "symlink" {
				link := filepath.Join(directory, "link.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			d, err := (SystemdDriver{Installation: path, Service: "worker", Unit: "untrusted.service", WorkerUser: "untrusted", UnitSHA256: "untrusted"}).resolveService()
			if failure == "" {
				if err != nil || d.Unit != "example-worker.service" || d.WorkerUser != "example-worker" || d.UnitSHA256 != strings.Repeat("a", 64) {
					t.Fatal("installation identity not resolved", err)
				}
			} else if err == nil {
				t.Fatal("invalid installation accepted")
			}
		})
	}
}

func TestInstallationIdentityCannotBeEncodedInBootstrap(t *testing.T) {
	raw, err := json.Marshal(SystemdDriver{Unit: "private.service", WorkerUser: "private-account", UnitSHA256: "private-digest"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private") {
		t.Fatal("derived service identity leaked into bootstrap")
	}
}
