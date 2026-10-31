package landing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SOCKSPort      = 1080
	nftTimeout     = 2 * time.Second
	nftOutputLimit = 16 << 20
)

var bridgeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

type nftObject = map[string]any
type nftDocument struct {
	Objects []map[string]nftObject `json:"nftables"`
}

func validateNFTPolicy(document nftDocument, table string, objects []map[string]nftObject, leaseElements bool) (bool, error) {
	wantedBytes, _ := json.Marshal(objects)
	var wanted []map[string]nftObject
	_ = json.Unmarshal(wantedBytes, &wanted) // Normalize JSON numbers and arrays.
	actual := map[string][]nftObject{}
	found := false
	for _, object := range document.Objects {
		for kind, value := range object {
			// Flow offload can bypass forward filtering, including established
			// connections. Do not change a host's unrelated offload policy.
			if kind == "flowtable" {
				return false, errors.New("landing: flow offload is unsupported")
			}
			if kind == "metainfo" {
				continue
			}
			if kind == "table" {
				if value["family"] != "inet" || value["name"] != table {
					continue
				}
				found = true
			} else if value["family"] != "inet" || value["table"] != table {
				continue
			}
			copy := nftObject{}
			for key, entry := range value {
				if key == "handle" {
					continue
				}
				if leaseElements && kind == "set" && (key == "elem" || key == "use" || key == "policy") {
					continue
				}
				copy[key] = entry
			}
			actual[kind] = append(actual[kind], copy)
		}
	}
	if !found {
		if len(actual) != 0 {
			return false, errors.New("landing: incomplete firewall ownership")
		}
		return false, nil
	}
	expected := map[string][]nftObject{}
	for _, object := range wanted {
		for kind, value := range object {
			expected[kind] = append(expected[kind], value)
		}
	}
	// Keep rule order exact within each chain; nft prints chain declarations
	// alongside their rules, rather than in the original transaction order.
	groupRules := func(values []nftObject) map[string][]nftObject {
		groups := map[string][]nftObject{}
		for _, value := range values {
			chain, _ := value["chain"].(string)
			if strings.HasPrefix(table, "glivela_entry_output_v2_") && chain == "destinations" {
				value["expr"] = localTLSReadbackExpression(value["expr"])
			}
			groups[chain] = append(groups[chain], value)
		}
		return groups
	}
	if !reflect.DeepEqual(groupRules(actual["rule"]), groupRules(expected["rule"])) {
		return false, errors.New("landing: firewall rules changed")
	}
	delete(actual, "rule")
	delete(expected, "rule")
	if !reflect.DeepEqual(actual, expected) {
		return false, errors.New("landing: firewall ownership or policy changed")
	}
	return true, nil
}

type boundedNFTOutput struct{ buffer bytes.Buffer }

func (b *boundedNFTOutput) Write(data []byte) (int, error) {
	if len(data) > nftOutputLimit-b.buffer.Len() {
		return 0, errors.New("landing: firewall response exceeds limit")
	}
	return b.buffer.Write(data)
}

// nft 1.0.6 silently drops table comments in JSON input and output. Keep
// native table metadata authoritative; rule comparison remains exact JSON.
func runNFT(ctx context.Context, input []byte, arguments ...string) ([]byte, error) {
	return runNFTMetadata(ctx, runNFTRaw, input, arguments...)
}

func runNFTMetadata(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error), input []byte, arguments ...string) ([]byte, error) {
	if input != nil && strings.Join(arguments, " ") == "--json --file -" {
		var batch struct {
			Commands []map[string]nftObject `json:"nftables"`
		}
		if err := json.Unmarshal(input, &batch); err != nil {
			return nil, err
		}
		var remaining []map[string]nftObject
		var create []string
		for _, command := range batch.Commands {
			operation := command["create"]
			table, ok := operation["table"].(map[string]any)
			if !ok || table["comment"] == nil {
				remaining = append(remaining, command)
				continue
			}
			name, nameOK := table["name"].(string)
			marker, markerOK := table["comment"].(string)
			if !nameOK || !markerOK || !nftOwnedTableName.MatchString(name) || !nftOwnedTableMarker.MatchString(marker) {
				remaining = append(remaining, command)
				continue
			}
			if len(command) != 1 || len(operation) != 1 || len(table) != 3 || table["family"] != "inet" {
				return nil, errors.New("landing: invalid owned firewall metadata")
			}
			create = append(create, "create table inet "+name+" { comment "+strconv.Quote(marker)+"; }\n")
		}
		if len(create) != 0 {
			// Exclusive create never adopts an existing table. Until the subsequent
			// atomic rule batch succeeds this table has no hooks or traffic effects.
			// Failures retain evidence and do not start the worker or delete resources.
			if _, err := run(ctx, []byte(strings.Join(create, "")), "--file", "-"); err != nil {
				return nil, err
			}
			if len(remaining) == 0 {
				return nil, nil
			}
			var err error
			input, err = json.Marshal(map[string]any{"nftables": remaining})
			if err != nil {
				return nil, err
			}
		}
	}
	output, err := run(ctx, input, arguments...)
	if err != nil || input != nil || len(arguments) < 2 || arguments[0] != "--json" || arguments[1] != "list" {
		return output, err
	}
	var document nftDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, err
	}
	changed := false
	for _, object := range document.Objects {
		table := object["table"]
		name, ok := table["name"].(string)
		if !ok || table["family"] != "inet" || table["comment"] != nil || !nftOwnedTableName.MatchString(name) {
			continue
		}
		// Read only the matching table, with its kernel handle. Never infer
		// ownership from a name, a rule shape, or the desired marker.
		text, err := run(ctx, nil, "--handle", "list", "table", "inet", name)
		if err != nil {
			return nil, err
		}
		marker, err := nftTableTextMarker(text, name, table["handle"])
		if err != nil {
			return nil, err
		}
		if marker != "" {
			table["comment"] = marker
			changed = true
		}
	}
	if changed {
		return json.Marshal(document)
	}
	return output, nil
}

var nftOwnedTableName = regexp.MustCompile(`^glivela_[a-z0-9_]+$`)
var nftOwnedTableMarker = regexp.MustCompile(`^glivela-[a-z0-9-]+:[a-f0-9]{64}$`)

func nftTableTextMarker(raw []byte, name string, handle any) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	number, ok := handle.(float64)
	if !ok || number <= 0 || number != float64(uint64(number)) || len(lines) < 2 || lines[0] != "table inet "+name+" { # handle "+strconv.FormatUint(uint64(number), 10) || strings.TrimSpace(lines[len(lines)-1]) != "}" {
		return "", errors.New("landing: firewall metadata snapshot changed")
	}
	// nft emits the table comment before any nested object. Looking elsewhere
	// could confuse a rule/chain comment with table ownership.
	line := strings.TrimSpace(lines[1])
	if !strings.HasPrefix(line, "comment ") {
		return "", nil
	}
	marker, err := strconv.Unquote(strings.TrimPrefix(line, "comment "))
	if err != nil {
		return "", errors.New("landing: invalid firewall table comment")
	}
	return marker, nil
}

func runNFTRaw(ctx context.Context, input []byte, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	// No shell expansion, environment-provided binary path or sensitive stderr.
	command := exec.CommandContext(ctx, "/usr/sbin/nft", arguments...)
	command.Stdin = bytes.NewReader(input)
	var output boundedNFTOutput
	command.Stdout = &output
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return nil, errors.New("landing: firewall operation failed")
	}
	return output.buffer.Bytes(), nil
}
