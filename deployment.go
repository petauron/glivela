package meridian

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
)

type DesiredArtifact struct {
	Revision     uint64 `json:"revision"`
	Config       []byte `json:"config"`
	ConfigSHA256 string `json:"configSha256"`
}

func BuildDesiredArtifact(plan XrayPlan) (DesiredArtifact, error) {
	config, err := RenderXrayConfiguration(plan)
	if err != nil {
		return DesiredArtifact{}, err
	}
	digest := sha256.Sum256(config)
	return DesiredArtifact{Revision: plan.Revision, Config: config, ConfigSHA256: hex.EncodeToString(digest[:])}, nil
}

func (a DesiredArtifact) Validate() error {
	if a.Revision == 0 || len(a.Config) == 0 || len(a.Config) > maxSubscriptionBytes || !json.Valid(a.Config) || !ValidIdentity(a.ConfigSHA256) {
		return errors.New("meridian: invalid desired artifact")
	}
	digest := sha256.Sum256(a.Config)
	if subtle.ConstantTimeCompare([]byte(a.ConfigSHA256), []byte(hex.EncodeToString(digest[:]))) != 1 {
		return errors.New("meridian: desired artifact digest changed")
	}
	var runtime struct {
		Routing struct{ Script string }
		DNS     struct{ Script string }
	}
	if json.Unmarshal(a.Config, &runtime) != nil || runtime.Routing.Script != "" || runtime.DNS.Script != "" {
		return errors.New("glivela: runtime artifacts must use official Xray configuration without scripts")
	}
	return nil
}

type AppliedReceipt struct {
	Revision     uint64 `json:"revision"`
	ConfigSHA256 string `json:"configSha256"`
	RuntimeReady bool   `json:"runtimeReady"`
}

func VerifyAppliedReceipt(desired DesiredArtifact, receipt AppliedReceipt) error {
	if desired.Validate() != nil || receipt.Revision != desired.Revision || !receipt.RuntimeReady || !ValidIdentity(receipt.ConfigSHA256) || subtle.ConstantTimeCompare([]byte(desired.ConfigSHA256), []byte(receipt.ConfigSHA256)) != 1 {
		return errors.New("meridian: applied receipt does not match desired Xray state")
	}
	return nil
}

type CounterSnapshot struct {
	CredentialID string `json:"credentialId"`
	UpBytes      int64  `json:"upBytes"`
	DownBytes    int64  `json:"downBytes"`
}

func (s CounterSnapshot) TotalBytes() int64 {
	if s.UpBytes > maxInt64-s.DownBytes {
		return maxInt64
	}
	return s.UpBytes + s.DownBytes
}

const maxInt64 = int64(^uint64(0) >> 1)

// ParseXrayUserCounters accepts the bounded result of Xray's StatsService
// query. Names are matched against the complete expected name, so an imported
// user label containing Xray's delimiter remains unambiguous.
func ParseXrayUserCounters(materials []CredentialMaterial, payload []byte) ([]CounterSnapshot, error) {
	if len(materials) > 65536 || len(payload) == 0 || len(payload) > maxSubscriptionBytes {
		return nil, errors.New("meridian: invalid Xray statistics input")
	}
	var response struct {
		Stats []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if decoder.Decode(&response) != nil {
		return nil, errors.New("meridian: invalid Xray statistics response")
	}
	values := map[string]int64{}
	seenStats := map[string]bool{}
	for _, stat := range response.Stats {
		if stat.Name == "" || !strings.HasPrefix(stat.Name, "user>>>") || seenStats[stat.Name] {
			return nil, errors.New("meridian: ambiguous Xray statistics response")
		}
		value, err := parseCounter(stat.Value)
		if err != nil {
			return nil, err
		}
		values[stat.Name], seenStats[stat.Name] = value, true
	}
	ordered := make([]CredentialMaterial, len(materials))
	copy(ordered, materials)
	slices.SortFunc(ordered, func(a, b CredentialMaterial) int {
		return strings.Compare(a.Credential.ID, b.Credential.ID)
	})
	seen := map[string]bool{}
	result := make([]CounterSnapshot, 0, len(ordered))
	for _, material := range ordered {
		if material.Validate() != nil || seen[material.Credential.ID] {
			return nil, errors.New("meridian: invalid Xray statistics credential")
		}
		seen[material.Credential.ID] = true
		prefix := "user>>>" + material.Credential.User + ">>>traffic>>>"
		result = append(result, CounterSnapshot{
			CredentialID: material.Credential.ID,
			UpBytes:      values[prefix+"uplink"],
			DownBytes:    values[prefix+"downlink"],
		})
	}
	return result, nil
}

func parseCounter(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		// Xray's protobuf JSON omits the value field for a zero counter.
		return 0, nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) == nil {
		value, err := strconv.ParseInt(number.String(), 10, 64)
		if err == nil && value >= 0 {
			return value, nil
		}
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		value, err := strconv.ParseInt(text, 10, 64)
		if err == nil && value >= 0 {
			return value, nil
		}
	}
	return 0, errors.New("meridian: invalid Xray traffic counter")
}
