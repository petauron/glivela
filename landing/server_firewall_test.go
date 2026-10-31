package landing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testServerFirewall() ServerFirewall {
	return ServerFirewall{EgressIP: "192.168.50.2", Revision: 1, Address: "100.64.0.8", Sources: []string{"100.64.0.9"}, Interface: "tailscale0", UID: 990}
}

func TestUDPRepliesRemainSourceAndDirectionScoped(t *testing.T) {
	policy := testServerFirewall()
	policy.Sources = append(policy.Sources, "100.64.0.10")
	policy.TCPOnlySources = []string{"100.64.0.10"}
	var replies []string
	for _, object := range policy.objects() {
		rule := object["rule"]
		if rule == nil || rule["chain"] != "destinations" {
			continue
		}
		encoded, _ := json.Marshal(rule["expr"])
		text := string(encoded)
		if strings.Contains(text, `"reply"`) && strings.Contains(text, `"udp"`) {
			replies = append(replies, text)
		}
	}
	if len(replies) != 1 {
		t.Fatalf("expected exactly one authorized UDP reply rule, got %d", len(replies))
	}
	for _, required := range []string{`"oifname"`, `"tailscale0"`, `"saddr"`, `"100.64.0.8"`, `"daddr"`, `"100.64.0.9"`, `"l4proto"`, `"direction"`, `"reply"`} {
		if !strings.Contains(replies[0], required) {
			t.Fatalf("UDP reply lost constraint %s", required)
		}
	}
	for _, forbidden := range []string{`"sport"`, `"100.64.0.10"`, `"accept"`} {
		if strings.Contains(replies[0], forbidden) {
			t.Fatalf("UDP reply has fixed port or authorization bypass: %s", forbidden)
		}
	}
}

func TestServerFirewallRejectsUnscopedIdentity(t *testing.T) {
	for _, change := range []func(*ServerFirewall){
		func(p *ServerFirewall) { p.UID = 0 },
		func(p *ServerFirewall) { p.UID = 65534 },
		func(p *ServerFirewall) { p.Address = "0.0.0.0" },
		func(p *ServerFirewall) { p.Interface = "tailscale0; flush ruleset" },
		func(p *ServerFirewall) { p.Sources = []string{"100.64.0.0/10"} },
		func(p *ServerFirewall) { p.Sources = []string{p.Address} },
		func(p *ServerFirewall) { p.Sources = append(p.Sources, p.Sources[0]) },
	} {
		policy := testServerFirewall()
		change(&policy)
		if err := policy.validate(); err == nil {
			t.Fatal("unsafe firewall identity was accepted")
		}
	}
}

func TestServerFirewallConfirmsLostReplyWithoutReplacingDrift(t *testing.T) {
	t.Run("legacy nft metadata remains verified", func(t *testing.T) {
		name := "glivela_fixture_metadata"
		marker := "glivela-entry-output-v1:" + strings.Repeat("a", 64)
		raw := "table inet " + name + " { # handle 9\n\tcomment " + `"` + marker + `"` + "\n}\n"
		got, err := nftTableTextMarker([]byte(raw), name, float64(9))
		if err != nil || got != marker {
			t.Fatalf("native metadata: %q %v", got, err)
		}
		if _, err := nftTableTextMarker([]byte(raw), name, float64(10)); err == nil {
			t.Fatal("changed kernel handle accepted")
		}
		nested := "table inet " + name + " { # handle 9\n chain output {\n comment \"" + marker + "\"\n }\n}"
		if got, err := nftTableTextMarker([]byte(nested), name, float64(9)); err != nil || got != "" {
			t.Fatal("nested comment claimed as table ownership")
		}
		calls := 0
		run := func(_ context.Context, input []byte, args ...string) ([]byte, error) {
			calls++
			if calls == 1 {
				if strings.Join(args, " ") != "--file -" || !strings.HasPrefix(string(input), "create table inet "+name+" { comment ") {
					t.Fatal("not exclusive native creation")
				}
			} else if calls == 2 {
				if strings.Contains(string(input), `"table":{`) || !strings.Contains(string(input), `"chain":`) {
					t.Fatal("table creation repeated or rules lost")
				}
			} else {
				t.Fatal("unexpected operation")
			}
			return nil, nil
		}
		batch, _ := json.Marshal(map[string]any{"nftables": []any{
			map[string]any{"create": map[string]any{"table": map[string]any{"family": "inet", "name": name, "comment": marker}}},
			map[string]any{"create": map[string]any{"chain": map[string]any{"family": "inet", "table": name, "name": "output"}}},
		}})
		if _, err := runNFTMetadata(context.Background(), run, batch, "--json", "--file", "-"); err != nil || calls != 2 {
			t.Fatalf("creation failed: %v", err)
		}
		calls = 0
		refused := func(_ context.Context, _ []byte, _ ...string) ([]byte, error) {
			calls++
			return nil, errors.New("table exists")
		}
		if _, err := runNFTMetadata(context.Background(), refused, batch, "--json", "--file", "-"); err == nil || calls != 1 {
			t.Fatal("existing table was adopted")
		}
	})
	policy := testServerFirewall()
	document := nftDocument{Objects: []map[string]nftObject{}}
	applies := 0
	run := func(_ context.Context, input []byte, _ ...string) ([]byte, error) {
		if input == nil {
			return json.Marshal(document)
		}
		applies++
		document.Objects = policy.objects()
		return nil, errors.New("simulated lost reply")
	}
	if err := policy.install(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := policy.install(context.Background(), run); err != nil || applies != 1 {
		t.Fatalf("idempotent apply: %v, writes %d", err, applies)
	}
	for _, object := range document.Objects {
		if chain := object["chain"]; chain != nil && chain["name"] == "output" {
			chain["prio"] = -400
		}
	}
	if err := policy.install(context.Background(), run); err == nil || applies != 1 {
		t.Fatalf("policy drift overwritten: %v, writes %d", err, applies)
	}
}

func TestServerFirewallRestrictsOnlyDedicatedService(t *testing.T) {
	policy := testServerFirewall()
	objects := policy.objects()
	table, _ := policy.identity()
	encoded, _ := json.Marshal(nftDocument{Objects: objects})
	var document nftDocument
	_ = json.Unmarshal(encoded, &document)
	if found, err := validateNFTPolicy(document, table, objects, false); err != nil || !found {
		t.Fatalf("rendered policy: %v", err)
	}
	data, _ := json.Marshal(objects)
	for _, required := range []string{`"skuid"`, `"reply"`, `"iifname"`, `"oifname"`, `"addr":"169.254.0.0"`, `"addr":"100.64.0.0"`} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("missing boundary %s", required)
		}
	}
	for _, forbidden := range []string{`"flush"`, `"established"`, `"related"`, `"log"`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("unexpected shared policy bypass %s", forbidden)
		}
	}
}

func TestServerFirewallRemovalReadsFreshSnapshot(t *testing.T) {
	policy := testServerFirewall()
	unrelated := []map[string]nftObject{
		{"table": {"family": "inet", "name": "user_policy"}},
		{"chain": {"family": "inet", "table": "user_policy", "name": "input"}},
		{"rule": {"family": "inet", "table": "user_policy", "chain": "input", "expr": []any{nftObject{"accept": nil}}}},
	}
	document := nftDocument{Objects: append(policy.objects(), unrelated...)}
	writes := 0
	run := func(_ context.Context, input []byte, _ ...string) ([]byte, error) {
		if input == nil {
			return json.Marshal(document)
		}
		writes++
		table, _ := policy.identity()
		want, _ := json.Marshal(nftObject{"nftables": []any{nftObject{"delete": nftObject{"table": nftObject{"family": "inet", "name": table}}}}})
		if string(input) != string(want) {
			t.Fatal("removal touched unrelated objects")
		}
		document.Objects = unrelated
		return nil, nil
	}
	if err := policy.remove(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := policy.remove(context.Background(), run); err != nil || writes != 1 {
		t.Fatalf("idempotent removal: %v, writes %d", err, writes)
	}
}
