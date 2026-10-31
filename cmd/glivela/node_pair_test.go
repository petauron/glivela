package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/petauron/glivela/control"
)

func TestReadPairedBootstrapKeepsBothRoles(t *testing.T) {
	cfg := pairedBootstrap()
	path := filepath.Join(t.TempDir(), "node.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readConfiguration(path)
	if err != nil || got.EntryNode == nil || got.LandingNode == nil || got.Mode != "node-pair" {
		t.Fatal("valid pair rejected", err)
	}
	cfg.Mode = "node"
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfiguration(path); err == nil {
		t.Fatal("single role accepted paired execution settings")
	}
}

func pairedBootstrap() configuration {
	entry := configuration{Mode: "node", Directory: "/private/entry", Installation: "/private/installation.json", Service: "node", Controller: "https://100.64.0.1:19443", Certificate: "/private/entry.crt", Key: "/private/entry.key", CA: "/private/ca.crt", Xray: control.SystemdDriver{Role: "entry", Installation: "/private/installation.json", Service: "entry-xray", Interface: "tailscale0"}}
	landing := entry
	landing.Directory = "/private/landing"
	landing.Certificate = "/private/landing.crt"
	landing.Key = "/private/landing.key"
	landing.Xray.Role = "landing"
	landing.Xray.Service = "landing-xray"
	return configuration{Mode: "node-pair", Directory: "/private/manager", Installation: entry.Installation, Service: "node", EntryNode: &entry, LandingNode: &landing}
}

func TestPairedBootstrapRequiresIndependentRoleOwnership(t *testing.T) {
	for _, fault := range []string{"", "journal", "nested-journal", "worker", "certificate", "key", "role", "controller", "installation", "recursive", "business", "single-role", "wrong-mode"} {
		t.Run(fault, func(t *testing.T) {
			cfg := pairedBootstrap()
			switch fault {
			case "journal":
				cfg.LandingNode.Directory = cfg.EntryNode.Directory
			case "nested-journal":
				cfg.LandingNode.Directory = cfg.EntryNode.Directory + "/landing"
			case "worker":
				cfg.LandingNode.Xray.Service = cfg.EntryNode.Xray.Service
			case "certificate":
				cfg.LandingNode.Certificate = cfg.EntryNode.Certificate
			case "key":
				cfg.LandingNode.Key = cfg.EntryNode.Key
			case "role":
				cfg.LandingNode.Xray.Role = "entry"
			case "controller":
				cfg.LandingNode.Controller = "https://100.64.0.2:19443"
			case "installation":
				cfg.LandingNode.Xray.Installation = "/private/foreign.json"
			case "recursive":
				cfg.EntryNode.EntryNode = cfg.LandingNode
			case "business":
				cfg.EntryNode.BusinessKey = "/private/business.key"
			case "single-role":
				cfg.LandingNode = nil
			case "wrong-mode":
				cfg.Mode = "node"
			}
			err := validateNodePair(cfg)
			if (err == nil) != (fault == "") {
				t.Fatalf("ownership boundary %q: %v", fault, err)
			}
		})
	}
}
