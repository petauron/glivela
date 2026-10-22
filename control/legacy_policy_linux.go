package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/petauron/glivela/landing"
)

// legacyPolicy is a one-time reader for the ownership journal, not a second
// runtime. In particular, an unspecified old exit must never silently become
// a new default exit during migration.
type legacyPolicy struct {
	EgressIP       string   `json:"egressIp,omitempty"`
	Revision       uint64   `json:"revision"`
	Address        string   `json:"address"`
	Sources        []string `json:"sources"`
	TCPOnlySources []string `json:"tcpOnlySources,omitempty"`
	Interface      string   `json:"interface"`
	UID            uint32   `json:"uid"`
}

func (s LegacyLandingSnapshot) migrationPlan() (landing.Plan, legacyPolicy, error) {
	var journal struct {
		NodeID   string          `json:"nodeId"`
		Revision uint64          `json:"revision"`
		UID      uint32          `json:"uid"`
		Policy   json.RawMessage `json:"policy"`
	}
	var policy legacyPolicy
	if json.Unmarshal(s.Journal, &journal) != nil || journal.NodeID != s.NodeID || journal.Revision != s.Revision {
		return landing.Plan{}, policy, errors.New("control: legacy policy identity differs")
	}
	decoder := json.NewDecoder(bytes.NewReader(journal.Policy))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&policy) != nil || decoder.Decode(&extra) != io.EOF || policy.Revision != s.Revision || policy.UID == 0 || policy.UID == 65534 || policy.UID != journal.UID || policy.Interface == "" || len(policy.Interface) > 15 {
		return landing.Plan{}, policy, errors.New("control: legacy policy is incomplete or unsupported")
	}
	for _, c := range policy.Interface {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return landing.Plan{}, policy, errors.New("control: invalid legacy interface")
		}
	}
	seen := map[string]bool{}
	for _, address := range policy.TCPOnlySources {
		if seen[address] || !slices.Contains(policy.Sources, address) {
			return landing.Plan{}, policy, errors.New("control: invalid legacy TCP-only grants")
		}
		seen[address] = true
	}
	plan := landing.Plan{Revision: policy.Revision, Address: policy.Address, EgressIP: policy.EgressIP}
	if plan.EgressIP == "" {
		// Earlier journals omitted the exit while the owned Dante file pinned
		// one IPv4 address. Read that exact retained value, never route discovery.
		for _, line := range strings.Split(string(s.Files["/etc/vastora-landing/danted.conf"].Contents), "\n") {
			line, _, _ = strings.Cut(line, "#")
			key, value, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(key) != "external" {
				continue
			}
			value = strings.TrimSpace(value)
			if plan.EgressIP != "" || !landing.ValidEgressIP(value) || strings.Contains(value, ":") {
				return landing.Plan{}, policy, errors.New("control: one retained literal IPv4 exit required")
			}
			plan.EgressIP = value
		}
	}
	for _, address := range policy.Sources {
		plan.Sources = append(plan.Sources, landing.Source{Address: address, TCPOnly: seen[address]})
	}
	if err := plan.Validate(); err != nil {
		return landing.Plan{}, policy, errors.New("control: legacy policy cannot be migrated without an explicit correction")
	}
	return plan, policy, nil
}
