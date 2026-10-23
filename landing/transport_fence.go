package landing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
)

// TransportListener is an already-owned proxy listener, not a new binding.
type TransportListener struct {
	Address string
	Port    int
	Network string
}

// TransportFence excludes client traffic while a drained worker is replaced.
// Its API listener is deliberately absent. No rules grant network access.
type TransportFence struct {
	Binding   string
	Listeners []TransportListener
}

func (f TransportFence) policy() (string, []map[string]nftObject, error) {
	if f.Binding == "" || len(f.Binding) > 4096 || len(f.Listeners) == 0 || len(f.Listeners) > 1024 {
		return "", nil, errors.New("landing: invalid transport fence")
	}
	raw, _ := json.Marshal(f)
	digest := sha256.Sum256(raw)
	identity := hex.EncodeToString(digest[:])
	table := "glivela_transport_" + identity[:24]
	objects := []map[string]nftObject{
		{"table": {"family": "inet", "name": table, "comment": "glivela-transport-v1:" + identity}},
		{"chain": {"family": "inet", "table": table, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}},
	}
	for _, listener := range f.Listeners {
		ip, err := netip.ParseAddr(listener.Address)
		if err != nil || ip.Zone() != "" || ip.IsMulticast() || ip.Is4In6() || listener.Port < 1 || listener.Port > 65535 || listener.Port == 10085 || listener.Network != "tcp" && listener.Network != "udp" {
			return "", nil, errors.New("landing: invalid transport listener")
		}
		family, nfproto := "ip", "ipv4"
		if ip.Is6() {
			family, nfproto = "ip6", "ipv6"
		}
		var expr []any
		if !ip.IsUnspecified() {
			expr = append(expr, nftObject{"match": nftObject{"op": "==", "left": nftObject{"payload": nftObject{"protocol": family, "field": "daddr"}}, "right": ip.String()}})
		} else {
			expr = append(expr, nftObject{"match": nftObject{"op": "==", "left": nftObject{"meta": nftObject{"key": "nfproto"}}, "right": nfproto}})
		}
		expr = append(expr, nftObject{"match": nftObject{"op": "==", "left": nftObject{"payload": nftObject{"protocol": listener.Network, "field": "dport"}}, "right": listener.Port}}, nftObject{"drop": nil})
		objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": table, "chain": "input", "expr": expr}})
	}
	return table, objects, nil
}

func (f TransportFence) Install(ctx context.Context) error {
	table, objects, err := f.policy()
	if err != nil {
		return err
	}
	return installOwnedFirewall(ctx, runNFT, table, objects)
}
func (f TransportFence) Verify(ctx context.Context) error {
	table, objects, err := f.policy()
	if err != nil {
		return err
	}
	return verifyOwnedFirewall(ctx, table, objects)
}
func (f TransportFence) Remove(ctx context.Context) error {
	table, objects, err := f.policy()
	if err != nil {
		return err
	}
	return removeOwnedFirewall(ctx, runNFT, table, objects)
}
