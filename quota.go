package glivela

import (
	"errors"
	"math"
	"slices"
	"strings"
)

type UsageMember struct {
	CredentialID string `json:"credentialId"`
	Baseline     int64  `json:"baseline"`
	Observed     int64  `json:"observed"`
	Active       bool   `json:"active"`
}

type AccessGate struct {
	CredentialID string `json:"credentialId"`
	Enabled      bool   `json:"enabled"`
}

type QuotaProjection struct {
	UsedBytes int64        `json:"usedBytes"`
	Enabled   bool         `json:"enabled"`
	Gates     []AccessGate `json:"gates"`
}

// ProjectQuota computes one account-wide usage value and projects only an
// on/off gate to each credential. It never splits the remaining quota between
// credentials, which would duplicate the plan or rewrite Xray on every sample.
func ProjectQuota(plan AccountPlan, members []UsageMember) (QuotaProjection, error) {
	if plan.Validate() != nil || len(members) == 0 || len(members) > 1024 {
		return QuotaProjection{}, errors.New("glivela: invalid shared quota")
	}
	ordered := slices.Clone(members)
	slices.SortFunc(ordered, func(a, b UsageMember) int { return strings.Compare(a.CredentialID, b.CredentialID) })
	var used int64
	for index, member := range ordered {
		if !ValidIdentifier(member.CredentialID) || index > 0 && member.CredentialID == ordered[index-1].CredentialID || member.Baseline < 0 || member.Observed < member.Baseline || member.Observed-member.Baseline > math.MaxInt64-used {
			return QuotaProjection{}, errors.New("glivela: invalid usage watermark")
		}
		used += member.Observed - member.Baseline
	}
	enabled := plan.Enabled && (plan.TotalBytes == 0 || used < plan.TotalBytes)
	projection := QuotaProjection{UsedBytes: used, Enabled: enabled, Gates: make([]AccessGate, 0, len(ordered))}
	for _, member := range ordered {
		projection.Gates = append(projection.Gates, AccessGate{CredentialID: member.CredentialID, Enabled: enabled && member.Active})
	}
	return projection, nil
}

func ObserveUsage(members []UsageMember, counters map[string]int64) ([]UsageMember, error) {
	result := slices.Clone(members)
	for index, member := range result {
		value, ok := counters[member.CredentialID]
		if !ok || value < member.Observed {
			return nil, errors.New("glivela: usage counters changed or are incomplete")
		}
		result[index].Observed = value
	}
	return result, nil
}

func ResetUsage(members []UsageMember) []UsageMember {
	result := slices.Clone(members)
	for index := range result {
		result[index].Baseline = result[index].Observed
	}
	return result
}
