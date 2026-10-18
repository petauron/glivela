package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// resolveService consumes the local installer's immutable resource inventory.
// It conveys no desired proxy state and grants no remote execution capability.
func (d SystemdDriver) resolveService() (SystemdDriver, error) {
	if !filepath.IsAbs(d.Installation) || filepath.Clean(d.Installation) != d.Installation || d.Service == "" {
		return SystemdDriver{}, errors.New("control: installation inventory and logical service required")
	}
	for parent := filepath.Dir(d.Installation); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return SystemdDriver{}, errors.New("control: unsafe installation directory")
		}
	}
	info, err := os.Lstat(d.Installation)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 65536 {
		return SystemdDriver{}, errors.New("control: unsafe installation inventory")
	}
	raw, err := os.ReadFile(d.Installation)
	if err != nil {
		return SystemdDriver{}, errors.New("control: installation inventory unavailable")
	}
	var inventory struct {
		Version  int `json:"version"`
		Services map[string]struct {
			Unit   string `json:"unit"`
			User   string `json:"user"`
			SHA256 string `json:"sha256"`
		} `json:"services"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&inventory) != nil || decoder.Decode(&extra) != io.EOF || inventory.Version != 1 {
		return SystemdDriver{}, errors.New("control: unsupported installation inventory")
	}
	service, ok := inventory.Services[d.Service]
	digest, err := hex.DecodeString(service.SHA256)
	if !ok || err != nil || len(digest) != 32 {
		return SystemdDriver{}, errors.New("control: installed service identity missing")
	}
	d.Unit, d.WorkerUser, d.UnitSHA256 = service.Unit, service.User, service.SHA256
	if _, err := d.installationNames(); err != nil {
		return SystemdDriver{}, err
	}
	return d, nil
}
