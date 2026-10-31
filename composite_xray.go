package glivela

import (
	"slices"
	"strconv"
	"strings"
)

// Rules choose the authorized exit; each SOCKS outbound's targetStrategy
// resolves the destination to that exit's family using official Xray DNS.
func compositeXrayRules(grant RouteGrant, publicSSH *PublicSSHPolicy, legacy bool) []any {
	scope := func(network, outbound string) map[string]any {
		return map[string]any{"type": "field", "inboundTag": []string{grant.InboundTag}, "user": []string{grant.Route.User}, "network": network, "outboundTag": outbound}
	}
	ports := make([]string, 0, len(legacyCompositeBlockedPorts))
	for _, port := range legacyCompositeBlockedPorts {
		if port != 22 || publicSSH == nil {
			ports = append(ports, strconv.Itoa(port))
		}
	}
	management := scope("tcp", "blocked")
	management["port"] = strings.Join(ports, ",")
	private := scope("tcp", "blocked")
	private["ip"] = slices.Clone(compositeBlockedCIDRs)
	ipv6 := scope("tcp", routeOutboundTag(grant.ID))
	ipv6["ip"] = []string{"::/0"}
	ipv4 := scope("tcp", routeOutboundTag(grant.ID)+"-ipv4")
	ipv4["ip"] = []string{"0.0.0.0/0"}
	rules := []any{scope("udp", "blocked")}
	if legacy {
		rules = append(rules, management)
	}
	return append(rules, private, ipv6, ipv4,
		// Unresolved destinations and credentials on a different inbound must
		// never fall through to the entry's native/default outbound.
		map[string]any{"type": "field", "user": []string{grant.Route.User}, "outboundTag": "blocked"},
	)
}
