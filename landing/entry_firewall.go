package landing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	glivela "github.com/petauron/glivela"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// EntryFirewall scopes post-resolution destination filtering to the dedicated
// native worker UID. Peer liveness is separately fenced by TrafficGate; probes
// run as the node, not as the worker, and cannot refresh their own permission.
type EntryFirewall struct {
	LocalTLSOrigin bool `json:"localTLSOrigin,omitempty"`

	PublicSSH      *glivela.PublicSSHPolicy `json:"publicSSH,omitempty"`
	UID            uint32
	Revision       uint64
	ExtraPeerPorts map[string][]int `json:"extraPeerPorts,omitempty"`
	PeerPorts      map[string]int   `json:"peerPorts,omitempty"`
	Peers          []string
	// Local, root-owned resolver configuration only; never supplied by peers.
	// Exclude from the stable table identity so resolver changes are reconciled
	// in the same owned table without conflicting output chains.
	DNS []string `json:"-"`
}

func (p EntryFirewall) validate() error {
	if err := p.PublicSSH.Validate(); err != nil {
		return err
	}
	if p.UID == 0 || p.UID == 65534 || p.Revision == 0 || len(p.Peers) > 1024 {
		return errors.New("landing: invalid native entry firewall identity")
	}
	seen := map[string]bool{}
	if len(p.DNS) > 16 {
		return errors.New("landing: too many entry resolvers")
	}
	for _, address := range p.DNS {
		ip, err := netip.ParseAddr(address)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.String() != address || seen[address] {
			return errors.New("landing: invalid entry resolver")
		}
		seen[address] = true
	}
	seen = map[string]bool{}
	for _, address := range p.Peers {
		if !(tailnetIPv4(address) || glivela.PublicTransportIPv4(address) || glivela.PublicTransportIPv6(address)) || seen[address] {
			return errors.New("landing: invalid native entry peer")
		}
		seen[address] = true
	}
	for address, port := range p.PeerPorts {
		if !seen[address] || (!glivela.PublicTransportIPv4(address) && !glivela.PublicTransportIPv6(address)) || port < 24000 || port > 24999 {
			return errors.New("landing: invalid public entry peer port")
		}
	}
	for address, ports := range p.ExtraPeerPorts {
		if !seen[address] || p.PeerPorts[address] == 0 || len(ports) > 1000 {
			return errors.New("landing: invalid additional peer ports")
		}
		used := map[int]bool{p.PeerPorts[address]: true}
		for _, port := range ports {
			if port < 24000 || port > 24999 || used[port] {
				return errors.New("landing: invalid additional peer port")
			}
			used[port] = true
		}
	}
	return nil
}

func (p EntryFirewall) identity() (string, string) {
	p.Peers = slices.Clone(p.Peers)
	slices.Sort(p.Peers)
	raw, _ := json.Marshal(p)
	digest := sha256.Sum256(raw)
	return "glivela_entry_output_v2_" + hex.EncodeToString(digest[:12]), "glivela-entry-output-v2:" + hex.EncodeToString(digest[:])
}

func (p EntryFirewall) objects() []map[string]nftObject {
	table, marker := p.identity()
	return p.renderObjects(table, marker, false)
}

func (p EntryFirewall) legacyObjects() (string, []map[string]nftObject) {
	table, marker := p.identity()
	table = strings.Replace(table, "_v2_", "_", 1)
	marker = strings.Replace(marker, "-v2:", "-v1:", 1)
	return table, p.renderObjects(table, marker, true)
}

func (p EntryFirewall) renderObjects(table, marker string, legacy bool) []map[string]nftObject {
	objects := []map[string]nftObject{
		{"table": {"family": "inet", "name": table, "comment": marker}},
		{"chain": {"family": "inet", "table": table, "name": "output", "type": "filter", "hook": "output", "prio": 20, "policy": "accept"}},
		{"chain": {"family": "inet", "table": table, "name": "destinations"}},
	}
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return nftObject{"payload": nftObject{"protocol": protocol, "field": field}}
	}
	rule := func(chain string, expr ...any) {
		objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": table, "chain": chain, "expr": expr}})
	}
	rule("output", match(nftObject{"meta": nftObject{"key": "skuid"}}, p.UID), nftObject{"jump": nftObject{"target": "destinations"}})
	// Responses to clients and the loopback statistics API are not new proxy
	// destination connections. There is no general established-flow bypass for
	// original-direction traffic to a newly resolved private destination.
	rule("destinations", match(nftObject{"ct": nftObject{"key": "direction"}}, "reply"), nftObject{"return": nil})
	if p.LocalTLSOrigin {
		// Docker may DNAT the loopback port before this output hook. Match the
		// original exact socket, never the container subnet. Freedom finalRules
		// still block private destinations requested by authenticated clients.
		origin := netip.MustParseAddrPort(glivela.ManagedLocalTLSTarget)
		rule("destinations",
			match(nftObject{"meta": nftObject{"key": "nfproto"}}, "ipv4"),
			match(nftObject{"meta": nftObject{"key": "l4proto"}}, "tcp"),
			match(nftObject{"ct": nftObject{"key": "daddr", "dir": "original", "family": "ip"}}, origin.Addr().String()),
			match(nftObject{"ct": nftObject{"key": "proto-dst", "dir": "original"}}, origin.Port()),
			nftObject{"return": nil})
	}
	resolvers := slices.Clone(p.DNS)
	slices.Sort(resolvers)
	for _, address := range resolvers {
		family := "ip"
		if netip.MustParseAddr(address).Is6() {
			family = "ip6"
		}
		for _, protocol := range []string{"tcp", "udp"} {
			rule("destinations", match(payload(family, "daddr"), address), match(payload(protocol, "dport"), 53), nftObject{"return": nil})
		}
	}
	peers := slices.Clone(p.Peers)
	slices.Sort(peers)
	for _, address := range peers {
		port := SOCKSPort
		if selected := p.PeerPorts[address]; selected != 0 {
			port = selected
		}
		family := "ip"
		if ip, _ := netip.ParseAddr(address); ip.Is6() {
			family = "ip6"
		}
		extra := slices.Clone(p.ExtraPeerPorts[address])
		slices.Sort(extra)
		for _, extraPort := range extra {
			rule("destinations", match(payload(family, "daddr"), address), match(payload("tcp", "dport"), extraPort), nftObject{"return": nil})
		}
		rule("destinations", match(payload(family, "daddr"), address), match(payload("tcp", "dport"), port), nftObject{"return": nil})
		// The landing independently retains its source-specific UDP policy.
		if glivela.PublicTransportIPv4(address) || glivela.PublicTransportIPv6(address) {
			rule("destinations", match(payload(family, "daddr"), address), match(payload("udp", "dport"), port), nftObject{"return": nil})
		} else {
			rule("destinations", match(payload("ip", "daddr"), address), match(nftObject{"meta": nftObject{"key": "l4proto"}}, "udp"), nftObject{"return": nil})
		}
	}
	for _, cidr := range blockedIPv4 {
		prefix := netip.MustParsePrefix(cidr)
		rule("destinations", match(payload("ip", "daddr"), nftObject{"prefix": nftObject{"addr": prefix.Addr().String(), "len": prefix.Bits()}}), nftObject{"drop": nil})
	}
	if legacy {
		for _, expr := range publicSSHDestinationRules(p.PublicSSH) {
			rule("destinations", expr...)
		}
		for _, portText := range strings.Split(legacyManagementPorts, ",") {
			port, _ := strconv.Atoi(portText)
			for _, protocol := range []string{"tcp", "udp"} {
				if port == 22 && protocol == "tcp" && p.PublicSSH != nil {
					continue
				}
				rule("destinations", match(payload(protocol, "dport"), port), nftObject{"drop": nil})
			}
		}
	}
	rule("destinations", match(nftObject{"meta": nftObject{"key": "nfproto"}}, "ipv4"), nftObject{"return": nil})
	for _, cidr := range blockedIPv6 {
		prefix := netip.MustParsePrefix(cidr)
		rule("destinations", match(payload("ip6", "daddr"), nftObject{"prefix": nftObject{"addr": prefix.Addr().String(), "len": prefix.Bits()}}), nftObject{"drop": nil})
	}
	rule("destinations", match(payload("ip6", "daddr"), nftObject{"prefix": nftObject{"addr": "2000::", "len": 3}}), nftObject{"return": nil})
	rule("destinations", nftObject{"drop": nil})
	return objects
}

// nft requires an address family when parsing ct daddr, but its JSON printer
// can omit that metadata and the redundant nfproto match. Normalize only this
// complete, exact TCP loopback-origin rule. Other addresses, ports, protocols,
// conntrack directions, verdicts and rule ordering still compare strictly.
func localTLSReadbackExpression(expression any) any {
	origin := netip.MustParseAddrPort(glivela.ManagedLocalTLSTarget)
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	canonical := []any{
		match(nftObject{"meta": nftObject{"key": "l4proto"}}, "tcp"),
		match(nftObject{"ct": nftObject{"key": "daddr", "dir": "original"}}, origin.Addr().String()),
		match(nftObject{"ct": nftObject{"key": "proto-dst", "dir": "original"}}, float64(origin.Port())),
		nftObject{"return": nil},
	}
	// validateNFTPolicy has already normalized map types and JSON numbers.
	for _, family := range []bool{false, true} {
		candidate := slices.Clone(canonical)
		if family {
			candidate[1] = match(nftObject{"ct": nftObject{"key": "daddr", "dir": "original", "family": "ip"}}, origin.Addr().String())
		}
		if reflect.DeepEqual(expression, candidate) {
			return canonical
		}
		candidate = append([]any{match(nftObject{"meta": nftObject{"key": "nfproto"}}, "ipv4")}, candidate...)
		if reflect.DeepEqual(expression, candidate) {
			return canonical
		}
	}
	return expression
}

// reconcileDNS replaces only the owned destination-chain rules when the
// root-owned resolver inventory changes. Every preexisting object must match
// the complete old policy before the atomic transaction is allowed.
func (p EntryFirewall) reconcileDNS(ctx context.Context) (bool, error) {
	table, _ := p.identity()
	data, err := runNFT(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil || len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil || document.Objects == nil {
		return false, errors.New("landing: cannot inspect entry firewall for DNS reconciliation")
	}
	found, currentErr := validateNFTPolicy(document, table, p.objects(), false)
	if currentErr == nil {
		return found, nil
	} // absent or already exact
	old := p
	old.DNS = nil
	seen := map[string]bool{}
	var handles []any
	for _, object := range document.Objects {
		rule := object["rule"]
		if rule == nil || rule["family"] != "inet" || rule["table"] != table || rule["chain"] != "destinations" {
			continue
		}
		handle, ok := rule["handle"].(float64)
		if !ok || handle <= 0 || handle != float64(uint64(handle)) {
			return false, errors.New("landing: entry firewall rule handle unavailable")
		}
		handles = append(handles, uint64(handle))
		expressions, ok := rule["expr"].([]any)
		if !ok || len(expressions) != 3 {
			continue
		}
		first, ok1 := expressions[0].(map[string]any)
		second, ok2 := expressions[1].(map[string]any)
		verdict, ok3 := expressions[2].(map[string]any)
		if !ok1 || !ok2 || !ok3 || len(verdict) != 1 {
			continue
		}
		if v, ok := verdict["return"]; !ok || v != nil {
			continue
		}
		match1, ok1 := first["match"].(map[string]any)
		match2, ok2 := second["match"].(map[string]any)
		if !ok1 || !ok2 || match1["op"] != "==" || match2["op"] != "==" {
			continue
		}
		left1, ok1 := match1["left"].(map[string]any)
		left2, ok2 := match2["left"].(map[string]any)
		if !ok1 || !ok2 {
			continue
		}
		dest, ok1 := left1["payload"].(map[string]any)
		port, ok2 := left2["payload"].(map[string]any)
		address, ok3 := match1["right"].(string)
		if !ok1 || !ok2 || !ok3 || dest["field"] != "daddr" || (dest["protocol"] != "ip" && dest["protocol"] != "ip6") || port["field"] != "dport" || (port["protocol"] != "tcp" && port["protocol"] != "udp") || match2["right"] != float64(53) {
			continue
		}
		if !seen[address] {
			old.DNS = append(old.DNS, address)
			seen[address] = true
		}
	}
	if err := old.validate(); err != nil {
		return false, currentErr
	}
	found, err = validateNFTPolicy(document, table, old.objects(), false)
	if err != nil || !found || len(handles) == 0 {
		return false, currentErr
	}
	commands := make([]any, 0, len(handles)+len(p.objects()))
	for _, handle := range handles {
		commands = append(commands, nftObject{"delete": nftObject{"rule": nftObject{"family": "inet", "table": table, "chain": "destinations", "handle": handle}}})
	}
	for _, object := range p.objects() {
		if rule := object["rule"]; rule != nil && rule["chain"] == "destinations" {
			commands = append(commands, nftObject{"add": nftObject{"rule": rule}})
		}
	}
	batch, err := json.Marshal(nftObject{"nftables": commands})
	if err != nil {
		return false, err
	}
	if _, err := runNFT(ctx, batch, "--json", "--file", "-"); err != nil {
		return false, err
	}
	err = verifyOwnedFirewall(ctx, table, p.objects())
	return err == nil, err
}

func (p EntryFirewall) Install(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	table, _ := p.identity()
	if _, err := p.reconcileDNS(ctx); err != nil {
		return err
	}
	if err := installOwnedFirewall(ctx, runNFT, table, p.objects()); err != nil {
		return err
	}
	oldTable, oldObjects := p.legacyObjects()
	return removeOwnedFirewall(ctx, runNFT, oldTable, oldObjects)
}
func (p EntryFirewall) Verify(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	// reconcileDNS already validates the full live ruleset. A DNS update also
	// reads back the transaction before returning. Never reuse it across rounds.
	found, err := p.reconcileDNS(ctx)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("landing: native firewall is missing or changed")
	}
	return nil
}

func (p EntryFirewall) Remove(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	table, _ := p.identity()
	if _, err := p.reconcileDNS(ctx); err != nil {
		return err
	}
	if err := removeOwnedFirewall(ctx, runNFT, table, p.objects()); err != nil {
		return err
	}
	oldTable, oldObjects := p.legacyObjects()
	return removeOwnedFirewall(ctx, runNFT, oldTable, oldObjects)
}
