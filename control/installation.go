package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type installedNativeService struct {
	Unit        string            `json:"unit"`
	User        string            `json:"user"`
	SHA256      string            `json:"sha256"`
	ConfigFiles map[string]string `json:"configFiles,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

type nativeInstallationInventory struct {
	Version  int                               `json:"version"`
	Services map[string]installedNativeService `json:"services"`
}

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
	var inventory nativeInstallationInventory
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

// InstalledMaintenanceFiles exposes only the current root service's declared
// persistent bootstrap/credential sources. RuntimeDirectory copies disappear
// at stop and must never be acknowledged as durable application edits.
// This reads immutable local ownership metadata; it is not a host command API.
func InstalledMaintenanceFiles(installation, logical string) (string, map[string]string, string, error) {
	invalid := errors.New("control: persistent owned service files required for offline maintenance")
	if os.Geteuid() != 0 || !filepath.IsAbs(installation) || filepath.Clean(installation) != installation || !validMaintenanceName(logical) {
		return "", nil, "", invalid
	}
	for parent := filepath.Dir(installation); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return "", nil, "", invalid
		}
		uid, err := entryFileUID(info)
		if err != nil || uid != 0 {
			return "", nil, "", invalid
		}
	}
	info, err := os.Lstat(installation)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 65536 {
		return "", nil, "", invalid
	}
	uid, err := entryFileUID(info)
	if err != nil || uid != 0 {
		return "", nil, "", invalid
	}
	raw, err := os.ReadFile(installation)
	var inventory nativeInstallationInventory
	if err != nil || decode(bytes.NewReader(raw), &inventory) != nil || inventory.Version != 1 {
		return "", nil, "", invalid
	}
	service, ok := inventory.Services[logical]
	name := strings.TrimSuffix(service.Unit, ".service")
	if !ok || service.User != "root" || !strings.HasSuffix(service.Unit, ".service") || !validMaintenanceName(name) || len(service.ConfigFiles) != 1 {
		return "", nil, "", invalid
	}
	unit := filepath.Join("/etc/systemd/system", service.Unit)
	info, err = os.Lstat(unit)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return "", nil, "", invalid
	}
	uid, err = entryFileUID(info)
	if err != nil || uid != 0 {
		return "", nil, "", invalid
	}
	raw, err = os.ReadFile(unit)
	digest := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(digest[:]) != service.SHA256 {
		return "", nil, "", invalid
	}
	base := filepath.Join(filepath.Dir(installation), logical)
	configuration := ""
	for key, path := range service.ConfigFiles {
		if filepath.IsAbs(key) || filepath.Clean(key) != key || strings.HasPrefix(key, "..") || path != filepath.Join(base, "config", key) {
			return "", nil, "", invalid
		}
		configuration = path
	}
	credentials := map[string]string{}
	for key, path := range service.Credentials {
		// Generated bootstrap snapshots are not application TLS credentials.
		if strings.HasPrefix(key, "config-") {
			continue
		}
		if !validMaintenanceName(key) || path != filepath.Join(base, "credentials", key) {
			return "", nil, "", invalid
		}
		credentials[key] = path
	}
	return configuration, credentials, "/run/" + name + "/", nil
}

func validMaintenanceName(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
