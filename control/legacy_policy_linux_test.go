package control

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLegacyMigrationPolicyPreservesSourceRestrictions(t *testing.T) {
	root, _ := legacyFixture(t)
	snapshot, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	plan, policy, err := snapshot.migrationPlan()
	if err != nil || plan.Address != "100.64.0.10" || plan.EgressIP != "8.8.8.8" || plan.Revision != 7 || policy.Interface != "mesh0" || policy.UID != 12345 || len(plan.Sources) != 2 || plan.Sources[0].TCPOnly || !plan.Sources[1].TCPOnly {
		t.Fatal("legacy policy changed during translation", err)
	}
	if _, err := NewDesired(plan); err != nil {
		t.Fatal("preserved plan cannot render official core config", err)
	}
	var journal map[string]any
	if err := json.Unmarshal(snapshot.Journal, &journal); err != nil {
		t.Fatal(err)
	}
	delete(journal["policy"].(map[string]any), "egressIp")
	snapshot.Journal, _ = json.Marshal(journal)
	for _, configuration := range []string{"external: 8.8.4.4\n", "external: eth0\n", "external: 8.8.4.4\nexternal: 8.8.8.8\n", "external: 2606:4700::1111\n", "# external: 8.8.4.4\n"} {
		snapshot.Files["/etc/vastora-landing/danted.conf"] = LegacyOwnedFile{Contents: []byte(configuration), Mode: 0600}
		got, old, err := snapshot.migrationPlan()
		if configuration == "external: 8.8.4.4\n" {
			if err != nil || got.EgressIP != "8.8.4.4" || old.EgressIP != "" || len(got.Sources) != len(plan.Sources) {
				t.Fatal("retained fixed exit or original firewall identity changed", err)
			}
		} else if err == nil {
			t.Fatal("ambiguous legacy exit accepted")
		}
	}
}

func TestLegacySnapshotRefusesAmbiguousMigrationPolicy(t *testing.T) {
	for _, scenario := range []string{"implicit exit", "wrong uid", "wrong revision", "unknown field", "foreign TCP-only source", "duplicate TCP-only source", "public listener", "all-sources", "invalid interface"} {
		t.Run(scenario, func(t *testing.T) {
			root, metadata := legacyFixture(t)
			p := metadata["policy"].(map[string]any)
			switch scenario {
			case "implicit exit":
				delete(p, "egressIp")
			case "wrong uid":
				p["uid"] = 12346
			case "wrong revision":
				p["revision"] = 8
			case "unknown field":
				p["allowAll"] = true
			case "foreign TCP-only source":
				p["tcpOnlySources"] = []string{"100.64.0.13"}
			case "duplicate TCP-only source":
				p["tcpOnlySources"] = []string{"100.64.0.12", "100.64.0.12"}
			case "public listener":
				p["address"] = "0.0.0.0"
			case "all-sources":
				p["sources"] = []string{"100.64.0.0/10"}
			case "invalid interface":
				p["interface"] = "mesh0\nother"
			}
			writeLegacyJournal(t, root, metadata)
			if _, err := snapshotLegacyLanding(root, "node-example", uint32(os.Getuid())); err == nil {
				t.Fatal("ambiguous policy accepted")
			}
		})
	}
}
