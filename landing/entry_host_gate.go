package landing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	glivela "github.com/petauron/glivela"
)

// The mark identifies only connections opened by the dedicated runtime GID
// to an authorized landing service. Glivela probes have a different GID and
// remain independent of the lease they are checking. It is a conntrack mark,
// not a packet routing mark.
const hostGateConnectionMark = 0x474c5650

func NewHostGate(peer PeerIdentity, gid uint32, revision uint64, transport ...glivela.PrivateTransport) (*TrafficGate, error) {
	if peer.Validate() != nil || gid == 0 || gid == 65534 || revision == 0 {
		return nil, errors.New("landing: invalid host gate identity")
	}
	identity, _ := json.Marshal(struct {
		Peer     PeerIdentity
		GID      uint32
		Revision uint64
	}{peer, gid, revision})
	endpoint, port := "", SOCKSPort
	if len(transport) > 1 {
		return nil, errors.New("landing: ambiguous public endpoint")
	}
	if len(transport) == 1 {
		endpoint, port = transport[0].PublicAddress, transport[0].ListenerPort()
	}
	if port != SOCKSPort && (port < 24000 || port > 24999 || endpoint == "") {
		return nil, errors.New("landing: invalid public listener port")
	}
	if endpoint != "" {
		if !glivela.PublicTransportIPv4(endpoint) && !glivela.PublicTransportIPv6(endpoint) {
			return nil, errors.New("landing: invalid public endpoint")
		}
		identity = append(identity, []byte("\npublic:"+endpoint)...)
	}
	if port != SOCKSPort {
		identity = append(identity, []byte("\nport:"+strconv.Itoa(port))...)
	}
	hash := sha256.Sum256(identity)
	return &TrafficGate{peer: peer, publicAddress: endpoint, port: port, gid: gid, revision: revision,
		table:  "glivela_entry_peer_host_" + hex.EncodeToString(hash[:12]),
		marker: "glivela-entry-peer-host-v1:" + hex.EncodeToString(hash[:]), run: runNFT}, nil
}

func (g *TrafficGate) tablePrefix() string {
	if g.gid != 0 {
		return "glivela_entry_peer_host_"
	}
	return "glivela_entry_peer_"
}

func (g *TrafficGate) scopeChain() string {
	if g.gid != 0 {
		return "output"
	}
	return "forward"
}

func (g *TrafficGate) validOwnership(name, marker string) bool {
	prefix := "glivela-entry-peer-v1:"
	if g.gid != 0 {
		prefix = "glivela-entry-peer-host-v1:"
	}
	tableHash := strings.TrimPrefix(name, g.tablePrefix())
	markerHash := strings.TrimPrefix(marker, prefix)
	decoded, err := hex.DecodeString(markerHash)
	return strings.HasPrefix(name, g.tablePrefix()) && strings.HasPrefix(marker, prefix) &&
		len(tableHash) == 24 && len(decoded) == 32 && err == nil && strings.ToLower(markerHash) == markerHash && strings.HasPrefix(markerHash, tableHash)
}

func (g *TrafficGate) hostObjects() []map[string]nftObject {
	network, addressType := "ip", "ipv4_addr"
	if ip, err := netip.ParseAddr(g.endpoint()); err == nil && ip.Is6() {
		network, addressType = "ip6", "ipv6_addr"
	}
	objects := []map[string]nftObject{
		{"table": {"family": "inet", "name": g.table, "comment": g.marker}},
		{"set": {"family": "inet", "table": g.table, "name": "allowed", "type": addressType, "flags": []string{"timeout"}, "timeout": int(gateDefaultLifetime.Seconds()), "size": 1}},
		{"chain": {"family": "inet", "table": g.table, "name": "output", "type": "filter", "hook": "output", "prio": 10, "policy": "accept"}},
		{"chain": {"family": "inet", "table": g.table, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}},
		{"chain": {"family": "inet", "table": g.table, "name": "outbound"}},
		{"chain": {"family": "inet", "table": g.table, "name": "inbound"}},
	}
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return nftObject{"payload": nftObject{"protocol": protocol, "field": field}}
	}
	ctMark := nftObject{"ct": nftObject{"key": "mark"}}
	rule := func(chain string, expr ...any) {
		objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": g.table, "chain": chain, "expr": expr}})
	}
	for _, protocol := range []string{"tcp", "udp"} {
		outbound := []any{match(nftObject{"meta": nftObject{"key": "skgid"}}, g.gid), match(payload(network, "daddr"), g.endpoint())}
		inbound := []any{match(ctMark, hostGateConnectionMark), match(payload(network, "saddr"), g.endpoint())}
		if protocol == "tcp" {
			outbound = append(outbound, match(payload("tcp", "dport"), g.listenerPort()))
			inbound = append(inbound, match(payload("tcp", "sport"), g.listenerPort()))
		} else if g.publicAddress != "" {
			outbound = append(outbound, match(payload("udp", "dport"), g.listenerPort()))
			inbound = append(inbound, match(payload("udp", "sport"), g.listenerPort()))
		} else {
			outbound = append(outbound, match(nftObject{"meta": nftObject{"key": "l4proto"}}, "udp"))
			inbound = append(inbound, match(nftObject{"meta": nftObject{"key": "l4proto"}}, "udp"))
		}
		rule("output", append(outbound, nftObject{"jump": nftObject{"target": "outbound"}})...)
		rule("input", append(inbound, nftObject{"jump": nftObject{"target": "inbound"}})...)
	}
	rule("outbound", nftObject{"mangle": nftObject{"key": ctMark, "value": hostGateConnectionMark}})
	rule("outbound", match(payload(network, "daddr"), "@allowed"), nftObject{"return": nil})
	rule("outbound", nftObject{"drop": nil})
	rule("inbound", match(payload(network, "saddr"), "@allowed"), nftObject{"return": nil})
	rule("inbound", nftObject{"drop": nil})
	return objects
}
