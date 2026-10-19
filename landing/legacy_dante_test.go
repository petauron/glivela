package landing

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyDanteRemovalRequiresExactPolicy(t *testing.T) {
	p := LegacyDanteFirewall(testServerFirewall())
	p.Sources = append(p.Sources, "100.64.0.10")
	p.TCPOnlySources = []string{"100.64.0.10"}
	for _, scenario := range []string{"owned", "missing", "foreign marker", "changed rule", "extra rule", "lost deletion"} {
		t.Run(scenario, func(t *testing.T) {
			objects := p.objects()
			table, _ := p.identity()
			foreign := map[string]nftObject{"table": {"family": "inet", "name": "unrelated"}}
			switch scenario {
			case "missing":
				objects = nil
			case "foreign marker":
				objects[0]["table"]["comment"] = "unowned"
			case "changed rule":
				for _, obj := range objects {
					if r := obj["rule"]; r != nil {
						r["expr"] = []any{nftObject{"accept": nil}}
						break
					}
				}
			case "extra rule":
				objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": table, "chain": "sources", "expr": []any{nftObject{"accept": nil}}}})
			}
			document := nftDocument{Objects: append(objects, foreign)}
			writes := 0
			run := func(_ context.Context, input []byte, _ ...string) ([]byte, error) {
				if input == nil {
					return json.Marshal(document)
				}
				writes++
				want, _ := json.Marshal(nftObject{"nftables": []any{nftObject{"delete": nftObject{"table": nftObject{"family": "inet", "name": table}}}}})
				if string(input) != string(want) {
					t.Fatal("deletion exceeded legacy ownership")
				}
				if scenario != "lost deletion" {
					document.Objects = []map[string]nftObject{foreign}
				}
				return nil, nil
			}
			err := p.remove(context.Background(), run)
			if scenario == "owned" || scenario == "missing" {
				if err != nil {
					t.Fatal(err)
				}
				if err := p.remove(context.Background(), run); err != nil {
					t.Fatal("retry failed", err)
				}
				wantWrites := 1
				if scenario == "missing" {
					wantWrites = 0
				}
				if writes != wantWrites || len(document.Objects) != 1 || document.Objects[0]["table"]["name"] != "unrelated" {
					t.Fatal("unrelated state changed")
				}
			} else if err == nil || scenario != "lost deletion" && writes != 0 {
				t.Fatal("unsafe removal accepted")
			}
		})
	}
}

func TestLegacyDantePortAndSourceBoundaries(t *testing.T) {
	p := LegacyDanteFirewall(testServerFirewall())
	raw, _ := json.Marshal(p.objects())
	for _, want := range []string{"vastora_landing_server_", "vastora-landing-server-v1:", `"range":[1081,1208]`, `"skuid"`, `"direction"`, `"reply"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatal("legacy policy differs", want)
		}
	}
	current, _ := json.Marshal(ServerFirewall(p).objects())
	if strings.Contains(string(current), `"range":[1081,1208]`) || strings.Contains(string(current), "vastora_landing_server_") {
		t.Fatal("legacy removal changed current runtime")
	}
}
