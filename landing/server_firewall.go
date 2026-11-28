package landing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	glivela "github.com/petauron/glivela"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ServerFirewall contains no passwords. UID must belong to the dedicated,
// non-login landing account, not root or another application. Inbound sources
// are exact node addresses on the actual tailscaled interface, not all tailnet
// members. The output chain runs after output DNAT, so post-resolution private
// addresses (including DNS rebinding) cannot bypass the destination restriction.
type ClientListenerPolicy struct {
	Interface string `json:"interface,omitempty"`
	EgressIP  string `json:"egressIp,omitempty"`
	Shared    bool   `json:"shared,omitempty"`
	Transport string `json:"transport,omitempty"`
	Address   string `json:"address,omitempty"`
	Port      int    `json:"port"`
	Source    string `json:"source"`
}

type ServerFirewall struct {
	UDPEgressIPs    []string                 `json:"udpEgressIps,omitempty"`
	Port            int                      `json:"port,omitempty"`
	IPv6Only        bool                     `json:"ipv6Only,omitempty"`
	PublicSSH       *glivela.PublicSSHPolicy `json:"publicSSH,omitempty"`
	ClientListeners []ClientListenerPolicy   `json:"clientListeners,omitempty"`
	EIHListeners    []EIHListenerPolicy      `json:"eihListeners,omitempty"`
	Public          bool                     `json:"public,omitempty"`
	EgressIP        string                   `json:"egressIp,omitempty"`
	Revision        uint64                   `json:"revision"`
	Address         string                   `json:"address"`
	Sources         []string                 `json:"sources"`
	TCPOnlySources  []string                 `json:"tcpOnlySources,omitempty"`
	Interface       string                   `json:"interface"`
	UID             uint32                   `json:"uid"`
}

func (policy ServerFirewall) listenerPort() int {
	if policy.Port != 0 {
		return policy.Port
	}
	return SOCKSPort
}

func (policy ServerFirewall) validate() error {
	if err := policy.PublicSSH.Validate(); err != nil {
		return err
	}
	for _, address := range []string{policy.Address, policy.EgressIP} {
		if err := policy.PublicSSH.RequireHost(address); err != nil {
			return err
		}
	}
	for _, listener := range policy.ClientListeners {
		if listener.EgressIP != "" && (!ValidEgressIP(listener.EgressIP) || policy.PublicSSH.RequireHost(listener.EgressIP) != nil) {
			return errors.New("landing: invalid client firewall exit")
		}
		if listener.Transport == "ipv6-ss2022" {
			if err := policy.PublicSSH.RequireHost(listener.Address); err != nil {
				return err
			}
		}
	}
	for _, listener := range policy.EIHListeners {
		if err := policy.PublicSSH.RequireHost(listener.Address); err != nil {
			return err
		}
		for _, ip := range listener.EgressIPs {
			if !ValidEgressIP(ip) || policy.PublicSSH.RequireHost(ip) != nil {
				return errors.New("landing: invalid EIH firewall exit")
			}
		}
		for _, relay := range listener.RelayEgress {
			if !ValidEgressIP(relay.Source) || policy.PublicSSH.RequireHost(relay.Source) != nil {
				return errors.New("landing: invalid EIH relay firewall exit")
			}
		}
	}
	if !ValidEgressIP(policy.EgressIP) {
		return errors.New("landing: invalid firewall egress IP")
	}
	seen := map[string]bool{}
	for _, ip := range policy.UDPEgressIPs {
		allowedEIH := slices.ContainsFunc(policy.EIHListeners, func(e EIHListenerPolicy) bool { return slices.Contains(e.EgressIPs, ip) })
		if seen[ip] || ip != policy.EgressIP && !slices.ContainsFunc(policy.ClientListeners, func(c ClientListenerPolicy) bool { return c.EgressIP == ip }) && !allowedEIH {
			return errors.New("landing: UDP exit is not an authorized egress")
		}
		seen[ip] = true
	}
	return policy.validateIdentity()
}

func (policy ServerFirewall) validateIdentity() error {
	if policy.Port != 0 && (policy.Port != 24000 || !policy.Public || policy.IPv6Only || slices.ContainsFunc(policy.Sources, func(source string) bool { return !slices.Contains(policy.TCPOnlySources, source) })) {
		return errors.New("landing: invalid public listener port")
	}
	validAddress := tailnetIPv4
	if policy.Public {
		validAddress = glivela.PublicTransportIPv4
	}
	if policy.IPv6Only {
		if !policy.Public || len(policy.Sources) != 0 || len(policy.TCPOnlySources) != 0 || !strings.Contains(policy.EgressIP, ":") {
			return errors.New("landing: invalid IPv6-only firewall")
		}
		validAddress = glivela.PublicTransportIPv6
	}
	if policy.Revision == 0 || !validAddress(policy.Address) || policy.UID == 0 || policy.UID == 65534 || !bridgeNamePattern.MatchString(policy.Interface) || len(policy.Sources) > 128 {
		return errors.New("landing: invalid native firewall identity")
	}
	seen := map[string]bool{}
	for _, source := range policy.Sources {
		if !validAddress(source) || source == policy.Address || seen[source] {
			return errors.New("landing: invalid native firewall source")
		}
		seen[source] = true
	}
	for _, source := range policy.TCPOnlySources {
		if !seen[source] {
			return errors.New("landing: TCP-only source is not authorized")
		}
	}
	ports := map[int]ClientListenerPolicy{}
	for _, c := range policy.ClientListeners {
		validTransport := (c.Transport == "" || c.Transport == glivela.IPv4ClientSS2022) && c.Address == "" && seen[c.Source] ||
			c.Transport == glivela.IPv4RelaySS2022 && c.Address == "" && !c.Shared && glivela.PublicTransportIPv4(c.Source) && c.Source != policy.Address ||
			c.Transport == "ipv6-ss2022" && glivela.PublicTransportIPv6(c.Address) && glivela.PublicTransportIPv6(c.Source) && c.Address != c.Source
		if c.Interface != "" {
			validTransport = glivela.PrivateClientIPv4(c.Address) && glivela.PrivateClientIPv4(c.Source) && c.Source != c.Address && bridgeNamePattern.MatchString(c.Interface) && c.Interface != "lo" && (c.Transport == "" || c.Transport == glivela.IPv4ClientSS2022)
		}
		if policy.IPv6Only && (c.Transport != "ipv6-ss2022" || c.Address != policy.Address) {
			return errors.New("landing: IPv4 listener in IPv6-only firewall")
		}
		previous, duplicate := ports[c.Port]
		if !policy.Public || c.Shared && c.Port != 24000 || c.Port < 24000 || c.Port > 24999 || duplicate && (!previous.Shared || !c.Shared || previous.EgressIP != c.EgressIP) || !validTransport {
			return errors.New("landing: invalid client listener firewall")
		}
		if policy.Port != 0 && c.Address == "" && c.Port == policy.Port && (!c.Shared || c.Transport != glivela.IPv4ClientSS2022 || c.EgressIP != "" && c.EgressIP != policy.EgressIP || len(policy.TCPOnlySources) != len(policy.Sources)) {
			return errors.New("landing: shared server firewall policy differs")
		}
		ports[c.Port] = c
	}
	seenEIH := map[string]bool{}
	for _, e := range policy.EIHListeners {
		isV4 := glivela.PublicTransportIPv4(e.Address)
		isV6 := glivela.PublicTransportIPv6(e.Address)
		if (!isV4 && !isV6) || e.Port != glivela.RelayPoolPort || seenEIH[e.Address] || len(e.Sources) == 0 || len(e.Sources) > 1024 {
			return errors.New("landing: invalid EIH listener firewall")
		}
		if e.Interface != "" && (!bridgeNamePattern.MatchString(e.Interface) || e.Interface == "lo") {
			return errors.New("landing: invalid EIH listener interface")
		}
		if policy.IPv6Only && (!isV6 || e.Address != policy.Address) {
			return errors.New("landing: IPv4 EIH listener in IPv6-only firewall")
		}
		if !policy.IPv6Only && policy.Address == e.Address && policy.listenerPort() == e.Port {
			return errors.New("landing: EIH firewall conflicts with server listener")
		}
		for _, c := range policy.ClientListeners {
			cAddr := policy.Address
			if c.Transport == "ipv6-ss2022" || c.Interface != "" {
				cAddr = c.Address
			}
			if cAddr == e.Address && c.Port == e.Port {
				return errors.New("landing: EIH firewall conflicts with client listener")
			}
		}
		seenSources := map[string]bool{}
		for _, src := range e.Sources {
			if src == e.Address || seenSources[src] || isV4 && !glivela.PublicTransportIPv4(src) || isV6 && !glivela.PublicTransportIPv6(src) {
				return errors.New("landing: invalid EIH firewall source")
			}
			seenSources[src] = true
		}
		for _, relay := range e.RelayEgress {
			if relay.Port != glivela.RelayPoolPort || !ValidEgressIP(relay.Source) || !(glivela.PublicTransportIPv4(relay.Address) || glivela.PublicTransportIPv6(relay.Address)) || relay.Address == e.Address || relay.Address == relay.Source {
				return errors.New("landing: invalid EIH relay firewall target")
			}
			srcIP, _ := netip.ParseAddr(relay.Source)
			dstIP, _ := netip.ParseAddr(relay.Address)
			if srcIP.Is6() != dstIP.Is6() {
				return errors.New("landing: EIH relay firewall family mismatch")
			}
		}
		seenEIH[e.Address] = true
	}
	return nil
}

func (policy ServerFirewall) digest() string {
	policy.Sources = slices.Clone(policy.Sources)
	slices.Sort(policy.Sources)
	policy.TCPOnlySources = slices.Clone(policy.TCPOnlySources)
	slices.Sort(policy.TCPOnlySources)
	policy.UDPEgressIPs = slices.Clone(policy.UDPEgressIPs)
	slices.Sort(policy.UDPEgressIPs)
	if len(policy.EIHListeners) != 0 {
		policy.EIHListeners = slices.Clone(policy.EIHListeners)
		for i := range policy.EIHListeners {
			policy.EIHListeners[i].Sources = slices.Clone(policy.EIHListeners[i].Sources)
			slices.Sort(policy.EIHListeners[i].Sources)
			policy.EIHListeners[i].EgressIPs = slices.Clone(policy.EIHListeners[i].EgressIPs)
			slices.Sort(policy.EIHListeners[i].EgressIPs)
			policy.EIHListeners[i].RelayEgress = slices.Clone(policy.EIHListeners[i].RelayEgress)
			slices.SortFunc(policy.EIHListeners[i].RelayEgress, func(a, b EIHRelayPolicy) int {
				if c := strings.Compare(a.Source, b.Source); c != 0 {
					return c
				}
				if c := strings.Compare(a.Address, b.Address); c != 0 {
					return c
				}
				return a.Port - b.Port
			})
		}
		slices.SortFunc(policy.EIHListeners, func(a, b EIHListenerPolicy) int { return strings.Compare(a.Address, b.Address) })
	}
	data, _ := json.Marshal(policy)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (policy ServerFirewall) identity() (string, string) {
	sum := policy.digest()
	if len(policy.EIHListeners) != 0 {
		return "glivela_landing_server_v4_" + sum[:16], "glivela-landing-server-v4:" + sum
	}
	if len(policy.UDPEgressIPs) != 0 {
		return "glivela_landing_server_v3_" + sum[:16], "glivela-landing-server-v3:" + sum
	}
	return "glivela_landing_server_v2_" + sum[:16], "glivela-landing-server-v2:" + sum
}

func (policy ServerFirewall) objects() []map[string]nftObject {
	table, marker := policy.identity()
	return policy.renderObjectsWithPolicy(table, marker, false, false, len(policy.UDPEgressIPs) != 0)
}

// legacy is used only by the one-time Dante removal verifier. It never
// installs or selects an old runtime policy.
func (policy ServerFirewall) renderObjects(table, marker string, legacy, management bool) []map[string]nftObject {
	return policy.renderObjectsWithPolicy(table, marker, legacy, management, false)
}

func (policy ServerFirewall) renderObjectsWithPolicy(table, marker string, legacy, management, blockUDP443 bool) []map[string]nftObject {
	objects := []map[string]nftObject{
		{"table": {"family": "inet", "name": table, "comment": marker}},
		{"chain": {"family": "inet", "table": table, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}},
		{"chain": {"family": "inet", "table": table, "name": "output", "type": "filter", "hook": "output", "prio": 10, "policy": "accept"}},
		{"chain": {"family": "inet", "table": table, "name": "sources"}},
		{"chain": {"family": "inet", "table": table, "name": "destinations"}},
	}
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return nftObject{"payload": nftObject{"protocol": protocol, "field": field}}
	}
	meta := func(key string) any { return nftObject{"meta": nftObject{"key": key}} }
	rule := func(chain string, expr ...any) {
		objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": table, "chain": chain, "expr": expr}})
	}
	for _, protocol := range []string{"tcp", "udp"} {
		if policy.IPv6Only {
			continue
		}
		var port any = policy.listenerPort()
		if protocol == "udp" {
			if legacy {
				port = nftObject{"range": []int{1081, 1208}}
			}
		}
		rule("input", match(payload("ip", "daddr"), policy.Address), match(payload(protocol, "dport"), port), nftObject{"jump": nftObject{"target": "sources"}})
	}
	// A shared primary socket is already governed by all exact server sources.
	// Do not append a client-only terminal drop that would revoke a migrated
	// source when its old client-chain record is disabled.
	listeners := slices.DeleteFunc(slices.Clone(policy.ClientListeners), func(c ClientListenerPolicy) bool {
		return policy.Port != 0 && c.Address == "" && c.Port == policy.Port
	})
	shared := map[string]bool{}
	for i, c := range listeners {
		family, address := "ip", policy.Address
		if c.Transport == "ipv6-ss2022" {
			family, address = "ip6", c.Address
		}
		iface := policy.Interface
		if c.Interface != "" {
			address, iface = c.Address, c.Interface
		}
		rule("input", match(payload(family, "daddr"), address), match(payload("tcp", "dport"), c.Port), match(meta("iifname"), iface), match(payload(family, "saddr"), c.Source), nftObject{"return": nil})
		if !c.Shared {
			for _, protocol := range []string{"tcp", "udp"} {
				rule("input", match(payload(family, "daddr"), address), match(payload(protocol, "dport"), c.Port), nftObject{"drop": nil})
			}
		} else {
			shared[address] = true
		}
		// Shared accepts are all emitted before the per-address final deny.
		if i == len(listeners)-1 {
			addresses := make([]string, 0, len(shared))
			for address := range shared {
				addresses = append(addresses, address)
			}
			slices.Sort(addresses)
			for _, address := range addresses {
				family := "ip"
				if glivela.PublicTransportIPv6(address) {
					family = "ip6"
				}
				for _, protocol := range []string{"tcp", "udp"} {
					rule("input", match(payload(family, "daddr"), address), match(payload(protocol, "dport"), 24000), nftObject{"drop": nil})
				}
			}
		}
		rule("destinations", match(meta("oifname"), iface), match(payload(family, "saddr"), address), match(payload(family, "daddr"), c.Source), match(payload("tcp", "sport"), c.Port), match(nftObject{"ct": nftObject{"key": "direction"}}, "reply"), nftObject{"return": nil})
	}
	eihListeners := slices.Clone(policy.EIHListeners)
	slices.SortFunc(eihListeners, func(a, b EIHListenerPolicy) int { return strings.Compare(a.Address, b.Address) })
	for _, e := range eihListeners {
		family := "ip"
		if strings.Contains(e.Address, ":") {
			family = "ip6"
		}
		iface := policy.Interface
		if e.Interface != "" {
			iface = e.Interface
		}
		eihSources := slices.Clone(e.Sources)
		slices.Sort(eihSources)
		for _, src := range eihSources {
			rule("input", match(payload(family, "daddr"), e.Address), match(payload("tcp", "dport"), e.Port), match(meta("iifname"), iface), match(payload(family, "saddr"), src), nftObject{"return": nil})
			rule("destinations", match(meta("oifname"), iface), match(payload(family, "saddr"), e.Address), match(payload(family, "daddr"), src), match(payload("tcp", "sport"), e.Port), match(nftObject{"ct": nftObject{"key": "direction"}}, "reply"), nftObject{"return": nil})
		}
		for _, protocol := range []string{"tcp", "udp"} {
			rule("input", match(payload(family, "daddr"), e.Address), match(payload(protocol, "dport"), e.Port), nftObject{"drop": nil})
		}
	}
	sources := slices.Clone(policy.Sources)
	slices.Sort(sources)
	for _, source := range sources {
		expr := []any{match(meta("iifname"), policy.Interface), match(payload("ip", "saddr"), source)}
		if slices.Contains(policy.TCPOnlySources, source) {
			expr = append(expr, match(meta("l4proto"), "tcp"))
		}
		rule("sources", append(expr, nftObject{"return": nil})...)
	}
	rule("sources", nftObject{"drop": nil})
	rule("output", match(meta("skuid"), policy.UID), nftObject{"jump": nftObject{"target": "destinations"}})
	// Only replies to an existing authorized SOCKS conversation may return to
	// the private network. There is no general established/related bypass.
	for _, source := range sources {
		for _, protocol := range []string{"tcp", "udp"} {
			if protocol == "udp" && slices.Contains(policy.TCPOnlySources, source) {
				continue
			}
			expr := []any{match(meta("oifname"), policy.Interface), match(payload("ip", "saddr"), policy.Address), match(payload("ip", "daddr"), source)}
			// Official Xray allocates a separate ephemeral UDP socket for each
			// association. Replies retain the dedicated UID, exact interface,
			// landing/source addresses and conntrack reply-direction checks;
			// they cannot be constrained to the TCP control listener's port.
			if protocol == "udp" && legacy {
				expr = append(expr, match(payload("udp", "sport"), nftObject{"range": []int{1081, 1208}}))
			} else if protocol == "tcp" {
				expr = append(expr, match(payload("tcp", "sport"), policy.listenerPort()))
			} else if policy.Public {
				expr = append(expr, match(payload("udp", "sport"), policy.listenerPort()))
			} else {
				expr = append(expr, match(meta("l4proto"), "udp"))
			}
			expr = append(expr, match(nftObject{"ct": nftObject{"key": "direction"}}, "reply"), nftObject{"return": nil})
			rule("destinations", expr...)
		}
	}
	for _, cidr := range blockedIPv4 {
		prefix := netip.MustParsePrefix(cidr)
		rule("destinations", match(payload("ip", "daddr"), nftObject{"prefix": nftObject{"addr": prefix.Addr().String(), "len": prefix.Bits()}}), nftObject{"drop": nil})
	}
	if management {
		for _, expr := range publicSSHDestinationRules(policy.PublicSSH) {
			rule("destinations", expr...)
		}
		for _, portString := range strings.Split(legacyManagementPorts, ",") {
			port, _ := strconv.Atoi(portString)
			for _, protocol := range []string{"tcp", "udp"} {
				if port == 22 && protocol == "tcp" && policy.PublicSSH != nil {
					continue
				}
				rule("destinations", match(payload(protocol, "dport"), port), nftObject{"drop": nil})
			}
		}
	}
	// Name resolution is the only IPv4 exception for an explicit IPv6 exit.
	// Fixed resolver destinations cannot carry arbitrary application connections.
	if policy.EgressIP != "" && !policy.IPv6Only {
		for _, resolver := range []string{"1.1.1.1", "1.0.0.1"} {
			for _, protocol := range []string{"tcp", "udp"} {
				rule("destinations", match(payload("ip", "daddr"), resolver), match(payload(protocol, "dport"), 53), nftObject{"return": nil})
			}
		}
	}
	addresses := []string{policy.EgressIP}
	for _, c := range policy.ClientListeners {
		if c.EgressIP != "" && !slices.Contains(addresses, c.EgressIP) {
			addresses = append(addresses, c.EgressIP)
		}
	}
	var relayEgress []EIHRelayPolicy
	for _, e := range eihListeners {
		for _, ip := range e.EgressIPs {
			if ip != "" && !slices.Contains(addresses, ip) {
				addresses = append(addresses, ip)
			}
		}
		for _, relay := range e.RelayEgress {
			if !slices.Contains(relayEgress, relay) {
				relayEgress = append(relayEgress, relay)
			}
		}
	}
	slices.SortFunc(relayEgress, func(a, b EIHRelayPolicy) int {
		if c := strings.Compare(a.Source, b.Source); c != 0 {
			return c
		}
		if c := strings.Compare(a.Address, b.Address); c != 0 {
			return c
		}
		return a.Port - b.Port
	})
	hasIPv6Egress := slices.ContainsFunc(addresses, func(ip string) bool { return strings.Contains(ip, ":") }) ||
		slices.ContainsFunc(relayEgress, func(r EIHRelayPolicy) bool { return strings.Contains(r.Source, ":") })
	if hasIPv6Egress {
		for _, cidr := range blockedIPv6 {
			prefix := netip.MustParsePrefix(cidr)
			rule("destinations", match(payload("ip6", "daddr"), nftObject{"prefix": nftObject{"addr": prefix.Addr().String(), "len": prefix.Bits()}}), nftObject{"drop": nil})
		}
	}
	if blockUDP443 {
		// XUDP full-cone associations can reuse an already-open UDP socket across
		// destination ports after Xray's first-packet routing check.
		rule("destinations", match(payload("udp", "dport"), 443), nftObject{"drop": nil})
	}
	for _, relay := range relayEgress {
		family := "ip"
		if strings.Contains(relay.Source, ":") {
			family = "ip6"
		}
		rule("destinations", match(payload(family, "saddr"), relay.Source), match(payload(family, "daddr"), relay.Address), match(payload("tcp", "dport"), relay.Port), nftObject{"return": nil})
	}
	for _, ip := range addresses {
		if strings.Contains(ip, ":") {
			rule("destinations", match(payload("ip6", "saddr"), ip), match(payload("ip6", "daddr"), nftObject{"prefix": nftObject{"addr": "2000::", "len": 3}}), match(meta("l4proto"), "tcp"), nftObject{"return": nil})
			if slices.Contains(policy.UDPEgressIPs, ip) {
				rule("destinations", match(payload("ip6", "saddr"), ip), match(payload("ip6", "daddr"), nftObject{"prefix": nftObject{"addr": "2000::", "len": 3}}), match(meta("l4proto"), "udp"), nftObject{"return": nil})
			}
		} else {
			for _, protocol := range []string{"tcp", "udp"} {
				if protocol == "udp" && ip != policy.EgressIP && !slices.Contains(policy.UDPEgressIPs, ip) {
					continue
				}
				// EgressIP is mandatory. Its IP payload match enforces IPv4;
				// nft strips a redundant nfproto condition on kernel read-back.
				expr := []any{match(meta("l4proto"), protocol), match(payload("ip", "saddr"), ip)}
				if legacy && policy.EgressIP == "" {
					// Exact historical read/remove shape; never installed by Xray.
					expr = []any{match(meta("nfproto"), "ipv4"), match(meta("l4proto"), protocol)}
				}
				rule("destinations", append(expr, nftObject{"return": nil})...)
			}
		}
	}
	rule("destinations", nftObject{"drop": nil}) // No other source or family may escape.
	return objects
}

// Install adds a complete, atomic policy and confirms its read-back. A
// different revision gets a different table, permitting safe overlap during a
// stopped-service transition; removing old rules requires the exact old plan.
func (policy ServerFirewall) Install(ctx context.Context) error {
	return policy.install(ctx, runNFT)
}

// Verify is read-only: a health observation must not silently repair drift.
func (policy ServerFirewall) Verify(ctx context.Context) error {
	if err := policy.validate(); err != nil {
		return err
	}
	table, _ := policy.identity()
	return verifyOwnedFirewall(ctx, table, policy.objects())
}

func verifyOwnedFirewall(ctx context.Context, table string, objects []map[string]nftObject) error {
	data, err := runNFT(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil || len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil {
		return errors.New("landing: cannot inspect native firewall")
	}
	found, err := validateNFTPolicy(document, table, objects, false)
	if err != nil || !found {
		return errors.New("landing: native firewall is missing or changed")
	}
	return nil
}

// Remove is used only while the owned native service is stopped. A changed
// or foreign table is never deleted to make a configuration update succeed.
func (policy ServerFirewall) Remove(ctx context.Context) error {
	return policy.remove(ctx, runNFT)
}

// RemoveMatchingEIH discovers per-EIH-listener interfaces from existing
// Glivela-owned v4 tables, reconstructs exact candidate policies, and removes
// only tables that pass full cryptographic identity and rule-by-rule checks.
func (policy ServerFirewall) RemoveMatchingEIH(ctx context.Context) error {
	return policy.removeMatchingEIH(ctx, runNFT)
}

func (policy ServerFirewall) removeMatchingEIH(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error)) error {
	if err := policy.validate(); err != nil {
		return err
	}
	if len(policy.EIHListeners) == 0 {
		return policy.remove(ctx, run)
	}
	data, err := run(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil || len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil {
		return errors.New("landing: cannot inspect native firewall before EIH removal")
	}
	v4Tables := map[string]bool{}
	tableIfaceByAddr := map[string]map[string]string{}
	for _, obj := range document.Objects {
		if tbl := obj["table"]; tbl != nil {
			name, _ := tbl["name"].(string)
			comment, _ := tbl["comment"].(string)
			if strings.HasPrefix(name, "glivela_landing_server_v4_") && strings.HasPrefix(comment, "glivela-landing-server-v4:") {
				v4Tables[name] = true
			}
		}
	}
	for _, obj := range document.Objects {
		rule := obj["rule"]
		if rule == nil || rule["chain"] != "input" {
			continue
		}
		tableName, _ := rule["table"].(string)
		if !v4Tables[tableName] {
			continue
		}
		exprs, _ := rule["expr"].([]any)
		var daddr, iif string
		hasPort := false
		for _, item := range exprs {
			m, _ := item.(map[string]any)
			match, _ := m["match"].(map[string]any)
			if match == nil {
				continue
			}
			left, _ := match["left"].(map[string]any)
			if payload, _ := left["payload"].(map[string]any); payload != nil {
				field, _ := payload["field"].(string)
				if field == "daddr" {
					if v, ok := match["right"].(string); ok {
						daddr = v
					}
				} else if field == "dport" {
					if v, ok := match["right"].(float64); ok && int(v) == glivela.RelayPoolPort {
						hasPort = true
					}
				}
			}
			if meta, _ := left["meta"].(map[string]any); meta != nil && meta["key"] == "iifname" {
				if v, ok := match["right"].(string); ok {
					iif = v
				}
			}
		}
		if hasPort && daddr != "" && iif != "" {
			if tableIfaceByAddr[tableName] == nil {
				tableIfaceByAddr[tableName] = map[string]string{}
			}
			tableIfaceByAddr[tableName][daddr] = iif
		}
	}
	tried := map[string]bool{}
	tryRemove := func(cand ServerFirewall) error {
		if cand.validate() != nil {
			return nil
		}
		table, _ := cand.identity()
		if tried[table] {
			return nil
		}
		tried[table] = true
		return cand.remove(ctx, run)
	}
	if err := tryRemove(policy); err != nil {
		return err
	}
	for _, ifaceMap := range tableIfaceByAddr {
		cand := policy
		cand.EIHListeners = slices.Clone(policy.EIHListeners)
		for i := range cand.EIHListeners {
			if obsIface := ifaceMap[cand.EIHListeners[i].Address]; obsIface != "" {
				cand.EIHListeners[i].Interface = obsIface
			}
		}
		if err := tryRemove(cand); err != nil {
			return err
		}
	}
	return nil
}

func (policy ServerFirewall) remove(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error)) error {
	if err := policy.validate(); err != nil {
		return err
	}
	table, _ := policy.identity()
	if err := removeOwnedFirewall(ctx, run, table, policy.objects()); err != nil {
		return err
	}
	return policy.removeLegacy(ctx, run)
}

func removeOwnedFirewall(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error), table string, objects []map[string]nftObject) error {
	data, err := run(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil || len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil {
		return errors.New("landing: cannot inspect native firewall before removal")
	}
	found, err := validateNFTPolicy(document, table, objects, false)
	if err != nil || !found {
		return err
	}
	command, _ := json.Marshal(nftObject{"nftables": []any{nftObject{"delete": nftObject{"table": nftObject{"family": "inet", "name": table}}}}})
	_, removeErr := run(ctx, command, "--json", "--file", "-")
	data, err = run(ctx, nil, "--json", "list", "ruleset")
	// Unmarshal reuses slice elements and their maps. A reordered ruleset
	// would otherwise retain keys from deleted objects and invent drift.
	document = nftDocument{}
	if err != nil || len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil {
		return errors.New("landing: cannot confirm native firewall removal")
	}
	found, err = validateNFTPolicy(document, table, objects, false)
	if err != nil || found {
		return errors.Join(removeErr, err, errors.New("landing: native firewall removal was not confirmed"))
	}
	return nil
}

func (policy ServerFirewall) install(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error)) error {
	if err := policy.validate(); err != nil {
		return err
	}
	table, _ := policy.identity()
	if err := installOwnedFirewall(ctx, run, table, policy.objects()); err != nil {
		return err
	}
	return policy.removeLegacy(ctx, run)
}

func installOwnedFirewall(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error), table string, objects []map[string]nftObject) error {
	snapshot := func() (bool, error) {
		data, err := run(ctx, nil, "--json", "list", "ruleset")
		var document nftDocument
		if err != nil || len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil || document.Objects == nil {
			return false, errors.New("landing: native firewall state is unavailable")
		}
		return validateNFTPolicy(document, table, objects, false)
	}
	found, err := snapshot()
	if err != nil || found {
		return err
	}
	commands := make([]any, 0, len(objects))
	for _, object := range objects {
		operation := "create"
		if object["rule"] != nil {
			operation = "add"
		}
		commands = append(commands, nftObject{operation: object})
	}
	data, _ := json.Marshal(nftObject{"nftables": commands})
	_, applyErr := run(ctx, data, "--json", "--file", "-")
	if found, err := snapshot(); err != nil || !found {
		return errors.Join(applyErr, err, errors.New("landing: native firewall installation was not confirmed"))
	}
	return nil
}

// removeLegacy accepts only the complete former UID-scoped policies. It cannot install them.
func (policy ServerFirewall) removeLegacy(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error)) error {
	sum := policy.digest()
	if len(policy.UDPEgressIPs) != 0 {
		table, marker := "glivela_landing_server_v2_"+sum[:16], "glivela-landing-server-v2:"+sum
		if err := removeOwnedFirewall(ctx, run, table, policy.renderObjects(table, marker, false, false)); err != nil {
			return err
		}
	}
	table, marker := "glivela_landing_server_"+sum[:16], "glivela-landing-server-v1:"+sum
	return removeOwnedFirewall(ctx, run, table, policy.renderObjects(table, marker, false, true))
}
