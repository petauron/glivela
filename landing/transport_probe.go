package landing

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// WithLocalProbe temporarily admits only a root-originated local TCP probe to
// an already-owned listener. The original exclusion is restored before return.
// Conntrack marks do not change packet routing or admit off-host traffic.
func (f TransportFence) WithLocalProbe(ctx context.Context, probe func(context.Context) error) (result error) {
	table, closed, err := f.policy()
	if err != nil {
		return err
	}
	local := transportProbePolicy(table, closed)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result = errors.Join(result, f.RestoreLocalProbe(cleanup))
	}()
	if err := replaceTransportPolicy(ctx, table, closed, local); err != nil {
		return err
	}
	return probe(ctx)
}

// RestoreLocalProbe closes an exact interrupted probe window. Call only from
// explicit maintenance after validating the retained checkpoint and identity.
// Ordinary health verification remains read-only and accepts only closed rules.
func (f TransportFence) RestoreLocalProbe(ctx context.Context) error {
	table, closed, err := f.policy()
	if err != nil {
		return err
	}
	if verifyOwnedFirewall(ctx, table, closed) == nil {
		return nil
	}
	return replaceTransportPolicy(ctx, table, transportProbePolicy(table, closed), closed)
}

// VerifyAbsent confirms completed maintenance has no remaining owned fence.
// Only an already-accounted checkpoint may use absence to resume normal probes.
func (f TransportFence) VerifyAbsent(ctx context.Context) error {
	table, closed, err := f.policy()
	if err != nil {
		return err
	}
	raw, err := runNFT(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil || len(raw) > nftOutputLimit || json.Unmarshal(raw, &document) != nil || document.Objects == nil {
		return errors.New("landing: transport fence absence not confirmed")
	}
	found, err := validateNFTPolicy(document, table, closed, false)
	if err != nil || found {
		return errors.New("landing: transport fence remains or changed")
	}
	return nil
}

func transportProbePolicy(table string, closed []map[string]nftObject) []map[string]nftObject {
	const probeMark = 0x474c5657
	objects := append([]map[string]nftObject(nil), closed[:2]...)
	objects = append(objects, map[string]nftObject{"chain": {"family": "inet", "table": table, "name": "local_probe", "type": "filter", "hook": "output", "prio": -11, "policy": "accept"}})
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	for _, object := range closed[2:] {
		rule := object["rule"]
		expr := rule["expr"].([]any)
		port := expr[len(expr)-2].(nftObject)["match"].(nftObject)["left"].(nftObject)["payload"].(nftObject)
		if port["protocol"] == "tcp" {
			output := []any{match(nftObject{"meta": nftObject{"key": "skuid"}}, 0), match(nftObject{"meta": nftObject{"key": "oifname"}}, "lo")}
			output = append(output, expr[:len(expr)-1]...)
			output = append(output, nftObject{"mangle": nftObject{"key": nftObject{"ct": nftObject{"key": "mark"}}, "value": probeMark}})
			objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": table, "chain": "local_probe", "expr": output}})
			input := []any{match(nftObject{"meta": nftObject{"key": "iifname"}}, "lo"), match(nftObject{"ct": nftObject{"key": "mark"}}, probeMark)}
			input = append(input, expr[:len(expr)-1]...)
			input = append(input, nftObject{"return": nil})
			objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": table, "chain": "input", "expr": input}})
		}
		objects = append(objects, object)
	}
	return objects
}

func replaceTransportPolicy(ctx context.Context, table string, before, after []map[string]nftObject) error {
	if err := verifyOwnedFirewall(ctx, table, before); err != nil {
		return err
	}
	// Preserve the table/comment. Flush and replace its chains atomically,
	// without the compatibility helper splitting a table-create operation.
	chain := func(name string) nftObject {
		return nftObject{"chain": nftObject{"family": "inet", "table": table, "name": name}}
	}
	commands := []any{nftObject{"flush": chain("input")}}
	for _, object := range before {
		if object["chain"] != nil && object["chain"]["name"] == "local_probe" {
			commands = append(commands, nftObject{"flush": chain("local_probe")}, nftObject{"delete": chain("local_probe")})
		}
	}
	for _, object := range after {
		if object["chain"] != nil && object["chain"]["name"] == "local_probe" {
			commands = append(commands, nftObject{"create": object})
		}
	}
	for _, object := range after {
		if object["rule"] != nil {
			commands = append(commands, nftObject{"add": object})
		}
	}
	raw, err := json.Marshal(nftObject{"nftables": commands})
	if err != nil {
		return err
	}
	_, applyErr := runNFT(ctx, raw, "--json", "--file", "-")
	return errors.Join(applyErr, verifyOwnedFirewall(ctx, table, after))
}
