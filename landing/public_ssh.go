package landing

import (
	"net/netip"
	"slices"
	"strings"

	glivela "github.com/petauron/glivela"
)

func managementPortRule(publicSSH *glivela.PublicSSHPolicy) map[string]any {
	ports := legacyManagementPorts
	if publicSSH != nil {
		ports = strings.TrimPrefix(ports, "22,")
	}
	return map[string]any{"type": "field", "port": ports, "outboundTag": "deny"}
}

// Drop-only rules in the existing UID-scoped post-DNAT destination chain.
// They grant nothing before private/family/source restrictions are checked.
func publicSSHDestinationRules(policy *glivela.PublicSSHPolicy) [][]any {
	if policy == nil {
		return nil
	}
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	tcp22 := match(nftObject{"payload": nftObject{"protocol": "tcp", "field": "dport"}}, 22)
	rules := [][]any{{tcp22, match(nftObject{"fib": nftObject{"result": "type", "flags": "daddr"}}, "local"), nftObject{"drop": nil}}}
	addresses := slices.Clone(policy.HostPublicAddresses)
	slices.Sort(addresses)
	for _, address := range addresses {
		family := "ip"
		if netip.MustParseAddr(address).Is6() {
			family = "ip6"
		}
		rules = append(rules, []any{tcp22, match(nftObject{"payload": nftObject{"protocol": family, "field": "daddr"}}, address), nftObject{"drop": nil}})
	}
	return rules
}
