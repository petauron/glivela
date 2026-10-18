package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type distributionMetadata struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Xray         struct {
		Version             string `json:"version"`
		SHA256              string `json:"sha256"`
		SourceArchiveSHA256 string `json:"sourceArchiveSHA256"`
	} `json:"xray"`
}

// ResolveInstallation consumes metadata from the verified distribution. The
// installer selects the immutable package, not the application's core version.
// Neither a node message nor a bootstrap field can override the core digest.
func (d SystemdDriver) ResolveInstallation() (SystemdDriver, error) {
	resolved, err := d.resolveDistribution(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return SystemdDriver{}, err
	}
	resolved, err = resolved.resolveService()
	if err != nil {
		return SystemdDriver{}, err
	}
	return resolved.ResolveWorker()
}

func (d SystemdDriver) resolveDistribution(targetOS, targetArch string) (SystemdDriver, error) {
	if !filepath.IsAbs(d.Distribution) || targetOS != "linux" || (targetArch != "amd64" && targetArch != "arm64") {
		return SystemdDriver{}, errors.New("control: unsupported native distribution")
	}
	for parent := d.Distribution; parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && (parent == d.Distribution || info.Mode()&os.ModeSticky == 0) {
			return SystemdDriver{}, errors.New("control: unsafe distribution directory")
		}
	}
	path := filepath.Join(d.Distribution, "runtime.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 4096 {
		return SystemdDriver{}, errors.New("control: unsafe distribution metadata")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return SystemdDriver{}, errors.New("control: distribution metadata unavailable")
	}
	var metadata distributionMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&metadata) != nil || decoder.Decode(&extra) != io.EOF || metadata.Version == "" ||
		metadata.OS != targetOS || metadata.Architecture != targetArch || metadata.Xray.Version != "26.7.28" {
		return SystemdDriver{}, errors.New("control: unsupported distribution metadata")
	}
	commit, commitErr := hex.DecodeString(metadata.Commit)
	archive, archiveErr := hex.DecodeString(metadata.Xray.SourceArchiveSHA256)
	if commitErr != nil || len(commit) != 20 || archiveErr != nil || len(archive) != 32 {
		return SystemdDriver{}, errors.New("control: distribution source identity missing")
	}
	d.Binary, d.BinarySHA256 = filepath.Join(d.Distribution, "xray"), metadata.Xray.SHA256
	if err := verifyExecutableFile(d.Binary, d.BinarySHA256); err != nil {
		return SystemdDriver{}, err
	}
	return d, nil
}
