package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/petauron/glivela/control"
)

// A paired host has one installed manager, with two independently authenticated
// single-role runtimes. Worker users, journals and firewall ownership stay
// separate: an entry's outbound permissions cannot widen the landing's policy.
func validateNodePair(cfg configuration) error {
	invalid := errors.New("node pair requires separate owned entry and landing runtimes")
	if cfg.EntryNode == nil || cfg.LandingNode == nil || cfg.Installation == "" || cfg.Service == "" {
		return invalid
	}
	expected := configuration{Mode: "node-pair", Directory: cfg.Directory, Installation: cfg.Installation, Service: cfg.Service, EntryNode: cfg.EntryNode, LandingNode: cfg.LandingNode}
	if !reflect.DeepEqual(cfg, expected) {
		return invalid
	}
	directories := []string{cfg.Directory, cfg.EntryNode.Directory, cfg.LandingNode.Directory}
	for i, path := range directories {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return invalid
		}
		for _, other := range directories[:i] {
			if path == other || strings.HasPrefix(path, other+"/") || strings.HasPrefix(other, path+"/") {
				return invalid
			}
		}
	}
	for i, child := range []*configuration{cfg.EntryNode, cfg.LandingNode} {
		role := []string{"entry", "landing"}[i]
		allowed := configuration{Mode: "node", Directory: child.Directory, Installation: cfg.Installation, Service: cfg.Service, Controller: child.Controller, Certificate: child.Certificate, Key: child.Key, CA: child.CA, Xray: child.Xray}
		if !reflect.DeepEqual(*child, allowed) || child.Xray.Role != role || child.Xray.Installation != cfg.Installation || child.Xray.Service == "" || child.Controller == "" {
			return invalid
		}
		for _, path := range []string{child.Certificate, child.Key, child.CA} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return invalid
			}
		}
	}
	a, b := cfg.EntryNode, cfg.LandingNode
	if a.Xray.Service == b.Xray.Service || a.Xray.Interface != b.Xray.Interface || a.Controller != b.Controller || a.CA != b.CA || a.Certificate == b.Certificate || a.Key == b.Key {
		return invalid
	}
	return nil
}

func runNodePair(ctx context.Context, cfg configuration) error {
	if err := validateNodePair(cfg); err != nil {
		return err
	}
	unlock, err := control.LockDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer unlock()
	children := []configuration{*cfg.EntryNode, *cfg.LandingNode}
	certificates := []string{}
	workers := []control.SystemdDriver{}
	// Validate both bindings before either child can activate a worker.
	for _, child := range children {
		driver, err := resolveNodeDriver(child.Xray)
		if err != nil {
			return err
		}
		key, err := os.Lstat(child.Key)
		if err != nil || !key.Mode().IsRegular() || key.Mode().Perm()&0077 != 0 {
			return errors.New("paired private key permissions invalid")
		}
		pair, err := tls.LoadX509KeyPair(child.Certificate, child.Key)
		if err != nil || len(pair.Certificate) == 0 {
			return errors.New("paired runtime identity unavailable")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return err
		}
		certificates = append(certificates, control.CertificateID(leaf))
		workers = append(workers, driver)
	}
	if certificates[0] == certificates[1] || workers[0].Unit == workers[1].Unit || workers[0].WorkerUID == workers[1].WorkerUID || workers[0].WorkerGID == workers[1].WorkerGID {
		return errors.New("paired roles must not share a certificate or worker identity")
	}
	group, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	for _, child := range children {
		go func() { done <- runConfiguration(group, child) }()
	}
	first := <-done
	cancel()
	return errors.Join(first, <-done)
}
