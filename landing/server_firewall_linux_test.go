//go:build linux

package landing

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// Opt-in integration must run in a fresh network namespace, never the host or
// container's normal namespace. No external interface or route is required.
func TestKernelFirewallLifecycle(t *testing.T) {
	if os.Getenv("GLIVELA_KERNEL_FIREWALL_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing kernel test outside a separate root network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "/usr/sbin/ip", "link", "add", "mesh-test", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("isolated interface: %s %v", output, err)
	}
	foreign := []byte(`{"nftables":[{"add":{"table":{"family":"inet","name":"glivela_fixture_unrelated"}}},{"add":{"chain":{"family":"inet","table":"glivela_fixture_unrelated","name":"guard","type":"filter","hook":"input","prio":50,"policy":"drop"}}}]}`)
	if _, err := runNFT(ctx, foreign, "--json", "--file", "-"); err != nil {
		t.Fatal(err)
	}
	before, err := runNFT(ctx, nil, "--json", "list", "table", "inet", "glivela_fixture_unrelated")
	if err != nil {
		t.Fatal(err)
	}
	for _, egress := range []string{"192.168.50.2", "2606:4700::1111"} {
		t.Run(egress, func(t *testing.T) { kernelPolicyLifecycle(t, ctx, egress) })
		t.Run("legacy-"+egress, func(t *testing.T) { kernelLegacyRemoval(t, ctx, egress) })
	}
	public := ServerFirewall{Public: true, Revision: 17, Address: "8.8.8.8", Sources: []string{"1.1.1.1"}, TCPOnlySources: []string{"1.1.1.1"}, Interface: "mesh-test", UID: 12345, EgressIP: "2606:4700::1111"}
	if err := public.Install(ctx); err != nil {
		t.Fatal("public install", err)
	}
	if err := public.Verify(ctx); err != nil {
		t.Fatal("public verify", err)
	}
	if err := public.Remove(ctx); err != nil {
		t.Fatal("public remove", err)
	}
	after, err := runNFT(ctx, nil, "--json", "list", "table", "inet", "glivela_fixture_unrelated")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unrelated firewall modified")
	}
}

func kernelLegacyRemoval(t *testing.T, ctx context.Context, egress string) {
	t.Helper()
	p := LegacyDanteFirewall{EgressIP: egress, Revision: 7, Address: "100.64.0.8", Sources: []string{"100.64.0.9", "100.64.0.10"}, TCPOnlySources: []string{"100.64.0.10"}, Interface: "mesh-test", UID: 12346}
	var commands []any
	for _, object := range p.objects() {
		op := "create"
		if object["rule"] != nil {
			op = "add"
		}
		commands = append(commands, nftObject{op: object})
	}
	raw, _ := json.Marshal(nftObject{"nftables": commands})
	if _, err := runNFT(ctx, raw, "--json", "--file", "-"); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(ctx); err != nil {
		t.Fatal("legacy kernel ownership rejected", err)
	}
	if err := p.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove(ctx); err != nil {
		t.Fatal("legacy removal retry failed", err)
	}
	if p.Verify(ctx) == nil {
		t.Fatal("removed legacy policy reported present")
	}
	// Recreate then introduce drift. Production removal must leave the table.
	if _, err := runNFT(ctx, raw, "--json", "--file", "-"); err != nil {
		t.Fatal(err)
	}
	table, _ := p.identity()
	mutation, _ := json.Marshal(nftObject{"nftables": []any{nftObject{"add": nftObject{"rule": nftObject{"family": "inet", "table": table, "chain": "sources", "expr": []any{nftObject{"accept": nil}}}}}}})
	if _, err := runNFT(ctx, mutation, "--json", "--file", "-"); err != nil {
		t.Fatal(err)
	}
	if p.Remove(ctx) == nil {
		t.Fatal("changed legacy table removed")
	}
	if _, err := runNFT(ctx, nil, "--json", "list", "table", "inet", table); err != nil {
		t.Fatal("changed table disappeared")
	}
}

func kernelPolicyLifecycle(t *testing.T, ctx context.Context, egress string) {
	t.Helper()
	policy, err := (Plan{Revision: 1, Address: "100.64.0.2", EgressIP: egress, Sources: []Source{{Address: "100.64.0.3", TCPOnly: egress != "192.168.50.2"}, {Address: "100.64.0.4", TCPOnly: true}}}).Firewall(12345, "mesh-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Install(ctx); err != nil {
		raw, _ := runNFT(ctx, nil, "--json", "list", "ruleset")
		var document nftDocument
		_ = json.Unmarshal(raw, &document)
		var expected []map[string]nftObject
		encoded, _ := json.Marshal(policy.objects())
		_ = json.Unmarshal(encoded, &expected)
		for _, chain := range []string{"input", "output", "sources", "destinations"} {
			var actualRules, expectedRules []nftObject
			for _, object := range document.Objects {
				if rule := object["rule"]; rule != nil && rule["chain"] == chain {
					delete(rule, "handle")
					actualRules = append(actualRules, rule)
				}
			}
			for _, object := range expected {
				if rule := object["rule"]; rule != nil && rule["chain"] == chain {
					expectedRules = append(expectedRules, rule)
				}
			}
			for i := range actualRules {
				if i < len(expectedRules) && !reflect.DeepEqual(actualRules[i], expectedRules[i]) {
					t.Logf("%s rule %d got=%v want=%v", chain, i, actualRules[i], expectedRules[i])
					break
				}
			}
		}
		t.Fatal(err)
	}
	if err := policy.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := policy.Install(ctx); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	if err := policy.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := policy.Verify(ctx); err == nil {
		t.Fatal("removed policy reported healthy")
	}
	if err := policy.Remove(ctx); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if err := policy.Install(ctx); err != nil {
		t.Fatal(err)
	}
	table, _ := policy.identity()
	mutation, _ := json.Marshal(nftObject{"nftables": []any{nftObject{"add": nftObject{"rule": nftObject{"family": "inet", "table": table, "chain": "destinations", "expr": []any{nftObject{"accept": nil}}}}}}})
	if _, err := runNFT(ctx, mutation, "--json", "--file", "-"); err != nil {
		t.Fatal(err)
	}
	if policy.Verify(ctx) == nil || policy.Install(ctx) == nil || policy.Remove(ctx) == nil {
		t.Fatal("changed rules were accepted or overwritten")
	}
	if _, err := runNFT(ctx, nil, "--json", "list", "table", "inet", table); err != nil {
		t.Fatal("changed table removed")
	}
	// Deliberately changed tables remain untouched and disappear with this
	// test-only network namespace; never flush them through production code.
}
