package control

import (
	"strings"
	"testing"
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
