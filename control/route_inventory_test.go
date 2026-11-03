package control

import (
	"encoding/json"
	"github.com/petauron/glivela/landing"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEntryInventoryRequiresExactPolicySources(t *testing.T) {
	for name, change := range map[string]func(*Node){
		"foreign source": func(n *Node) {
			n.RouteEntries["entry-a"] = RouteEntry{CertificateID: strings.Repeat("b", 64), Address: "100.64.0.99"}
		},
		"same as landing": func(n *Node) {
			n.RouteEntries["entry-a"] = RouteEntry{CertificateID: n.CertificateID, Address: "100.64.0.3"}
		},
		"extra source": func(n *Node) {
			n.RouteEntries["entry-b"] = RouteEntry{CertificateID: strings.Repeat("c", 64), Address: "100.64.0.4"}
		},
		"bad identity": func(n *Node) { n.RouteEntries["entry-a"] = RouteEntry{CertificateID: "invalid", Address: "100.64.0.3"} },
	} {
		t.Run(name, func(t *testing.T) {
			node := Node{ID: "landing-a", CertificateID: strings.Repeat("a", 64), Desired: artifact(1), RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: strings.Repeat("b", 64), Address: "100.64.0.3"}}}
			change(&node)
			if store(t).Put(node) == nil {
				t.Fatal("unbound entry inventory accepted")
			}
		})
	}
}

func TestProvisioningCannotManufactureEntryCoverage(t *testing.T) {
	s := store(t)
	cert, entryCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	d := artifact(1)
	node := Node{ID: "landing-a", CertificateID: cert, Desired: d}
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, cert, d)
	p := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	if s.AssignRouteChecks([]RouteCheck{{CertificateID: entryCert, Request: p}}) == nil {
		t.Fatal("probe batch defined its own entry inventory")
	}
	node.RouteEntries = map[string]RouteEntry{"entry-a": {CertificateID: entryCert, Address: "100.64.0.3"}}
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	delete(node.RouteEntries, "entry-a")
	if len(s.nodes[cert].RouteEntries) != 1 {
		t.Fatal("external caller changed enrolled inventory after Put")
	}
	reportRuntime(t, s, cert, d)
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entryCert, Request: p}}); err != nil {
		t.Fatal(err)
	}
	node.RouteEntries = map[string]RouteEntry{"entry-a": {CertificateID: strings.Repeat("c", 64), Address: "100.64.0.3"}}
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	if len(s.nodes[cert].Checks) != 0 {
		t.Fatal("changed entry identity retained previous health proof")
	}
}

func TestPartialEntryInventorySurvivesRestartWithoutAcceptance(t *testing.T) {
	s := store(t)
	plan := *artifact(1).Landing
	plan.Sources = append(plan.Sources, landing.Source{Address: "100.64.0.4"})
	desired, err := NewDesired(plan)
	if err != nil {
		t.Fatal(err)
	}
	cert, entryCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	node := Node{ID: "landing-a", CertificateID: cert, Desired: desired, RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: entryCert, Address: "100.64.0.3"}}}
	if err := s.Put(node); err != nil {
		t.Fatal("valid partial enrollment blocked the controller", err)
	}
	probe := RouteProbe{AttemptID: "attempt-a", SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: desired.Revision, ConfigSHA256: desired.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	node.Checks = map[string]RouteCheck{"entry-a": {CertificateID: entryCert, Request: probe, IssuedAt: time.Now().UTC()}}
	if completeRouteInventory(node, node.Checks) {
		t.Fatal("partial inventory manufactured full route acceptance")
	}
	raw, err := json.Marshal([]Node{node})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenStore(s.path)
	if err != nil {
		t.Fatal("retained partial enrollment blocked restart", err)
	}
	retained := restarted.nodes[cert]
	if len(retained.RouteEntries) != 1 || retained.Desired.ConfigSHA256 != desired.ConfigSHA256 || len(retained.Desired.Landing.Sources) != 2 {
		t.Fatal("restart changed authorized configuration or retained bindings")
	}
	if len(retained.Checks) != 0 || completeRouteInventory(retained, retained.Checks) {
		t.Fatal("restart reused partial observations as readiness proof")
	}
}
