package landing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// EntryFirewall scopes post-resolution destination filtering to the dedicated
// native worker UID. Peer liveness is separately fenced by TrafficGate; probes
// run as the node, not as the worker, and cannot refresh their own permission.
type EntryFirewall struct {
	UID      uint32
	Revision uint64
	Peers    []string
}

func (p EntryFirewall) validate() error {
	if p.UID == 0 || p.UID == 65534 || p.Revision == 0 || len(p.Peers) > 1024 {
		return errors.New("landing: invalid native entry firewall identity")
	}
	seen := map[string]bool{}
	for _, address := range p.Peers {
		if !tailnetIPv4(address) || seen[address] {
			return errors.New("landing: invalid native entry peer")
		}
		seen[address] = true
	}
	return nil
}

func (p EntryFirewall) identity() (string, string) {
	p.Peers = slices.Clone(p.Peers)
	slices.Sort(p.Peers)
	raw, _ := json.Marshal(p)
	digest := sha256.Sum256(raw)
	return "glivela_entry_output_" + hex.EncodeToString(digest[:12]), "glivela-entry-output-v1:" + hex.EncodeToString(digest[:])
}

func (p EntryFirewall) objects() []map[string]nftObject {
	table, marker := p.identity()
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
	peers := slices.Clone(p.Peers)
	slices.Sort(peers)
	for _, address := range peers {
		rule("destinations", match(payload("ip", "daddr"), address), match(payload("tcp", "dport"), SOCKSPort), nftObject{"return": nil})
		// The landing independently retains its source-specific UDP policy.
		rule("destinations", match(payload("ip", "daddr"), address), match(nftObject{"meta": nftObject{"key": "l4proto"}}, "udp"), nftObject{"return": nil})
	}
	for _, cidr := range blockedIPv4 {
		prefix := netip.MustParsePrefix(cidr)
		rule("destinations", match(payload("ip", "daddr"), nftObject{"prefix": nftObject{"addr": prefix.Addr().String(), "len": prefix.Bits()}}), nftObject{"drop": nil})
	}
	for _, portText := range strings.Split(managementPorts, ",") {
		port, _ := strconv.Atoi(portText)
		for _, protocol := range []string{"tcp", "udp"} {
			rule("destinations", match(payload(protocol, "dport"), port), nftObject{"drop": nil})
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

func (p EntryFirewall) Install(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	table, _ := p.identity()
	return installOwnedFirewall(ctx, runNFT, table, p.objects())
}
func (p EntryFirewall) Verify(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	table, _ := p.identity()
	return verifyOwnedFirewall(ctx, table, p.objects())
}
func (p EntryFirewall) Remove(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	table, _ := p.identity()
	return removeOwnedFirewall(ctx, runNFT, table, p.objects())
}
