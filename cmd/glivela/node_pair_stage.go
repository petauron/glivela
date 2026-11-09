package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/petauron/glivela/control"
)

// stage-node-pair changes only the owned bootstrap. The installer must already
// have supplied the second manual worker; no service, journal or grant is made
// here. The existing role keeps its EXACT driver binding and state directory.
func stageNodePairCommand(parent context.Context, args []string, output io.Writer) error {
	f := flag.NewFlagSet("stage-node-pair", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("config", "", "persistent installed single-role bootstrap")
	candidate := f.String("pair", "", "private complete paired bootstrap")
	apply := f.Bool("apply", false, "back up and atomically save the checked bootstrap")
	if f.Parse(args) != nil || f.NArg() != 0 || *path == "" || *candidate == "" || *path == *candidate || os.Geteuid() != 0 {
		return errors.New("root pairing requires persistent config and a separate private pair candidate")
	}
	original, err := privatePairFile(*path)
	if err != nil {
		return err
	}
	before, err := readConfiguration(*path)
	if err != nil {
		return err
	}
	if before.Installation == "" || before.Service == "" {
		return errors.New("installed native node required")
	}
	source, credentials, prefix, err := control.InstalledMaintenanceFiles(before.Installation, before.Service)
	if err != nil || source != *path {
		return errors.New("persistent bootstrap ownership not confirmed")
	}
	installationBefore, err := os.ReadFile(before.Installation)
	if err != nil {
		return err
	}
	next, err := readConfiguration(*candidate)
	if err != nil || next.Mode != "node-pair" || next.Installation != before.Installation || next.Service != before.Service {
		return errors.New("pair must use the same installed manager")
	}
	backup := filepath.Join(next.Directory, "single-role-bootstrap.json")
	if *candidate == backup || *path == backup {
		return errors.New("pair candidate cannot occupy the recovery slot")
	}
	if before.Mode == "node-pair" {
		if !reflect.DeepEqual(before, next) {
			return errors.New("existing pair differs; not a pairing retry")
		}
		if err := rootPairDirectory(next.Directory); err != nil {
			return err
		}
		raw, err := privatePairFile(backup)
		var saved configuration
		if err != nil || json.Unmarshal(raw, &saved) != nil {
			return errors.New("pair recovery bootstrap unavailable")
		}
		if _, err := preservedPairRole(saved, next); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]string{"status": "paired-bootstrap-already-saved"})
	}
	if _, err := privatePairFile(*candidate); err != nil {
		return err
	}
	other, err := preservedPairRole(before, next)
	if err != nil {
		return err
	}
	if err := control.CheckPairingDirectories(before.Installation, before.Service, []string{before.Directory, next.Directory, other.Directory}); err != nil {
		return err
	}
	for _, dir := range []string{before.Directory, next.Directory, other.Directory} {
		if err := rootPairDirectory(dir); err != nil {
			return err
		}
		unlock, err := control.LockDirectory(dir)
		if err != nil {
			return errors.New("stop the owned manager before pairing; state remains in use")
		}
		defer unlock()
	}
	files, err := os.ReadDir(other.Directory)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.Name() != ".glivela.lock" {
			return errors.New("additional role state must be unused; retained data is not reinitialized")
		}
	}
	identities := []configuration{*next.EntryNode, *next.LandingNode}
	for i := range identities {
		if err := resolvePairCredentials(&identities[i], credentials, prefix); err != nil {
			return err
		}
	}
	if err := verifyPairCertificates(identities); err != nil {
		return err
	}
	installed, err := resolveNodeDriver(before.Xray)
	if err != nil {
		return err
	}
	additional, err := resolveNodeDriver(other.Xray)
	if err != nil || installed.Unit == additional.Unit || installed.WorkerUID == additional.WorkerUID || installed.WorkerGID == additional.WorkerGID {
		return errors.New("second independent installed worker required")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if err := additional.CheckPairingWorker(ctx, other.Directory); err != nil {
		return err
	}
	var driver control.Driver = installed
	if installed.Role == "entry" {
		driver = &control.NativeEntryDriver{SystemdDriver: installed, Directory: before.Directory}
	}
	if err := (&control.NativeRuntime{Directory: before.Directory, Driver: driver}).CheckPairingSource(ctx); err != nil {
		return errors.New("existing role must have an owned running committed state; no automatic recovery during pairing")
	}
	status := "pairing-preflight-passed"
	if *apply {
		installationNow, err := os.ReadFile(before.Installation)
		if err != nil || !bytes.Equal(installationBefore, installationNow) {
			return errors.New("installation changed during pairing; rerun preflight")
		}
		if _, _, _, err := control.InstalledMaintenanceFiles(before.Installation, before.Service); err != nil {
			return err
		}
		if err := savePairBackup(backup, original); err != nil {
			return err
		}
		if err := savePrivateConfiguration(*path, original, next); err != nil {
			return err
		}
		status = "paired-bootstrap-saved-manager-restart-required"
	}
	return json.NewEncoder(output).Encode(map[string]string{"status": status})
}

func preservedPairRole(before, next configuration) (*configuration, error) {
	invalid := errors.New("pair must preserve the existing native role, identity, worker and journal")
	if before.Mode != "node" || before.Installation == "" || before.Entry != nil || before.EntryProvision || before.LegacyEntryCheckpoint != "" || validateNodePair(next) != nil || next.Installation != before.Installation || next.Service != before.Service {
		return nil, invalid
	}
	primary, other := next.LandingNode, next.EntryNode
	if before.Xray.Role == "entry" {
		primary, other = next.EntryNode, next.LandingNode
	} else if before.Xray.Role == "" {
		before.Xray.Role = "landing"
	}
	if !reflect.DeepEqual(before, *primary) {
		return nil, invalid
	}
	return other, nil
}

func resolvePairCredentials(cfg *configuration, credentials map[string]string, prefix string) error {
	for _, value := range []*string{&cfg.Certificate, &cfg.Key, &cfg.CA} {
		if len(*value) >= len(prefix) && (*value)[:len(prefix)] == prefix {
			path, ok := credentials[(*value)[len(prefix):]]
			if !ok {
				return errors.New("paired runtime credential is not declared by the installed manager")
			}
			*value = path
		}
	}
	return nil
}

func verifyPairCertificates(children []configuration) error {
	if len(children) != 2 {
		return errors.New("two role identities required")
	}
	var previous *x509.Certificate
	for _, child := range children {
		info, err := os.Lstat(child.Key)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<10 {
			return errors.New("private bounded role key required")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return errors.New("role key must be root owned")
		}
		for _, path := range []string{child.Certificate, child.CA} {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
				return errors.New("bounded owned certificate and CA files required")
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != 0 {
				return errors.New("role certificate and CA must be root owned")
			}
		}
		pair, err := tls.LoadX509KeyPair(child.Certificate, child.Key)
		if err != nil || len(pair.Certificate) == 0 {
			return errors.New("role certificate and key do not match")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return errors.New("invalid role certificate")
		}
		pem, err := os.ReadFile(child.CA)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return errors.New("role CA unavailable")
		}
		chain := x509.NewCertPool()
		for _, raw := range pair.Certificate[1:] {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return errors.New("invalid role certificate chain")
			}
			chain.AddCert(cert)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: chain, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return errors.New("role certificate is not currently trusted for node authentication")
		}
		if previous != nil && (control.CertificateID(previous) == control.CertificateID(leaf) || reflect.DeepEqual(previous.PublicKey, leaf.PublicKey)) {
			return errors.New("roles require distinct certificates and private keys")
		}
		previous = leaf
	}
	return nil
}

func rootPairDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("pair requires existing private installed state directories")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errors.New("pair state must be root owned")
	}
	return nil
}

func privatePairFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
		return nil, errors.New("private bounded pairing file required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, errors.New("pairing file must be root owned")
	}
	return os.ReadFile(path)
}

func savePairBackup(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
			return errors.New("unsafe existing pair recovery bootstrap")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			return errors.New("pair recovery ownership changed")
		}
		saved, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(saved, raw) {
			return errors.New("existing pair recovery bootstrap differs")
		}
	} else if err != nil {
		return err
	} else {
		defer file.Close()
		if _, err := file.Write(raw); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
