package meridian

import "errors"

// EgressPolicy controls the final destination family of native traffic.
// Fixed routes keep their SOCKS transport and the landing's own egress policy.
type EgressPolicy string

const (
	EgressAuto     EgressPolicy = "auto"
	EgressIPv4Only EgressPolicy = "ipv4_only"
	EgressIPv6Only EgressPolicy = "ipv6_only"
)

// The zero value means the policy was not specified and leaves Xray's system
// address selection unchanged. Unknown policies must never become auto.
func (p EgressPolicy) Validate() error {
	switch p {
	case "", EgressAuto, EgressIPv4Only, EgressIPv6Only:
		return nil
	default:
		return errors.New("meridian: unsupported native egress policy")
	}
}

func nativeXrayOutbound(policy EgressPolicy) map[string]any {
	outbound := map[string]any{"protocol": "freedom", "tag": "direct"}
	var strategy, blockedFamily string
	switch policy {
	case EgressIPv4Only:
		strategy, blockedFamily = "ForceIPv4", "::/0"
	case EgressIPv6Only:
		strategy, blockedFamily = "ForceIPv6", "0.0.0.0/0"
	default:
		return outbound
	}
	// Force* controls domain resolution only. finalRules also rejects literal
	// addresses and every XUDP destination/response in an existing association.
	// Add no allow rule: Xray's server-side private-target protection remains.
	// Uses the post-26.9.8 sockopt resolution path, including UDP domains.
	outbound["streamSettings"] = map[string]any{"sockopt": map[string]any{"domainStrategy": strategy}}
	outbound["settings"] = map[string]any{
		"finalRules": []any{map[string]any{
			"action": "block", "ip": []string{blockedFamily},
		}},
	}
	return outbound
}
