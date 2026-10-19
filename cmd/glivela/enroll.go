package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/petauron/glivela/control"
)

// Offline enrollment is app-owned installation/migration tooling. It binds
// supplied client certificates to preserved IDs and typed proxy plans without
// sending business state or private keys through the host's task channel.
func enrollNodesCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("enroll-nodes", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "private controller bootstrap")
	inventoryPath := flags.String("inventory", "", "private node enrollment inventory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *inventoryPath == "" {
		return errors.New("controller bootstrap and private enrollment inventory required")
	}
	cfg, err := readMaintenanceConfiguration(*configPath)
	if err != nil || cfg.Mode != "controller" {
		return errors.New("controller configuration required")
	}
	unlock, err := control.LockDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer unlock()
	info, err := os.Lstat(*inventoryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
		return errors.New("private enrollment file required")
	}
	raw, err := os.ReadFile(*inventoryPath)
	if err != nil {
		return err
	}
	defer clear(raw)
	var inventory []struct {
		ID           string                        `json:"id"`
		Certificate  string                        `json:"certificate"`
		Desired      control.Desired               `json:"desired"`
		RouteEntries map[string]control.RouteEntry `json:"routeEntries,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&inventory) != nil || decoder.Decode(&extra) != io.EOF || len(inventory) == 0 || len(inventory) > 1024 {
		return errors.New("invalid enrollment inventory")
	}
	ca, err := os.ReadFile(cfg.CA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("controller CA required")
	}
	nodes := make([]control.Node, 0, len(inventory))
	seenIDs, seenCertificates := map[string]bool{}, map[string]bool{}
	for _, item := range inventory {
		block, rest := pem.Decode([]byte(item.Certificate))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("one node client certificate required")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || certificate.IsCA {
			return errors.New("node leaf certificate required")
		}
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return errors.New("node certificate is not valid for this controller")
		}
		id := control.CertificateID(certificate)
		if slices.Contains(cfg.Administrators, id) || seenCertificates[id] || seenIDs[item.ID] || item.Desired.Validate() != nil {
			return errors.New("conflicting node role or desired state")
		}
		seenIDs[item.ID], seenCertificates[id] = true, true
		nodes = append(nodes, control.Node{ID: item.ID, CertificateID: id, Desired: item.Desired, RouteEntries: item.RouteEntries})
	}
	store, err := control.OpenStore(filepath.Join(cfg.Directory, "nodes.json"))
	if err != nil {
		return err
	}
	if err := store.LoadBusiness(cfg.BusinessKey); err != nil {
		return err
	}
	// Put strips receipts and refuses role/identity conflicts. An interrupted
	// batch retains completed enrollments; retrying never recreates credentials
	// or resets business data. No enrollment result is a runtime health result.
	for _, node := range nodes {
		if err := store.Put(node); err != nil {
			return err
		}
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}{"nodes-enrolled-awaiting-runtime-and-route-verification", len(nodes)})
}
