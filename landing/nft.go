package landing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"regexp"
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

func runNFT(ctx context.Context, input []byte, arguments ...string) ([]byte, error) {
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
