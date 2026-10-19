package glivela

import (
	"errors"
	"slices"
)

// EgressPolicy controls the final destination family of native traffic.
// Fixed routes keep their SOCKS transport and the landing's own egress policy.
type EgressPolicy string

const (
	EgressAuto     EgressPolicy = "auto"
	EgressIPv4Only EgressPolicy = "ipv4_only"
	EgressIPv6Only EgressPolicy = "ipv6_only"
)

// The zero value keeps automatic family selection, not the host/control-plane
// resolver. Every native policy uses Glivela's explicit business DNS.
func (p EgressPolicy) Validate() error {
	switch p {
	case "", EgressAuto, EgressIPv4Only, EgressIPv6Only:
		return nil
	default:
		return errors.New("glivela: unsupported native egress policy")
	}
}

func nativeXrayOutbound(policy EgressPolicy) map[string]any {
	strategy, blockedFamily := "ForceIP", ""
	switch policy {
	case EgressIPv4Only:
		strategy, blockedFamily = "ForceIPv4", "::/0"
	case EgressIPv6Only:
		strategy, blockedFamily = "ForceIPv6", "0.0.0.0/0"
	}
	blocked := slices.Clone(compositeBlockedCIDRs)
	if blockedFamily != "" {
		blocked = append(blocked, blockedFamily)
	}
	// 26.7.28 supports Freedom's own strategy and post-resolution finalRules.
	// Setting only a socket strategy leaves Freedom's AsIs preflight using
	// the system resolver. Do not add an allow rule that bypasses its guards.
	return map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"domainStrategy": strategy, "finalRules": []any{map[string]any{"action": "block", "ip": blocked}}}}
}
