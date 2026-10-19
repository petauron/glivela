package control

import (
	"errors"
	"net/netip"
	"slices"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// EntryNetwork is Glivela business policy, not a host capability description.
// EgressID and tailscaled ID belong to different namespaces. Never infer one
// from the other or trust a reachable IP as an authenticated peer identity.
type EntryNetwork struct {
	Source *landing.PeerIdentity `json:"source,omitempty"`
	Peers  []EntryPeer           `json:"peers"`
}

type EntryPeer struct {
	EgressID     string               `json:"egressId"`
	Identity     landing.PeerIdentity `json:"identity"`
	Target       string               `json:"target"`
	ExpectedExit string               `json:"expectedExit"`
}

func (n EntryNetwork) clone() EntryNetwork {
	n.Peers = slices.Clone(n.Peers)
	if n.Source != nil {
		source := *n.Source
		n.Source = &source
	}
	return n
}

func (n EntryNetwork) validate(plan glivela.XrayPlan) error {
	invalid := errors.New("control: entry transport identity and routed peers differ")
	if len(n.Peers) > 1024 || len(n.Peers) == 0 && n.Source != nil || len(n.Peers) != 0 && (n.Source == nil || n.Source.Validate() != nil) {
		return invalid
	}
	used := make(map[string]bool)
	for _, grant := range plan.Grants {
		used[grant.EgressID] = true
		if grant.IPv4EgressID != "" {
			used[grant.IPv4EgressID] = true
		}
	}
	if len(used) != len(n.Peers) {
		return invalid
	}
	configured := make(map[string]glivela.RoutePeer, len(plan.Peers))
	for _, peer := range plan.Peers {
		configured[peer.EgressID] = peer
	}
	ids, keys, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, peer := range n.Peers {
		route, found := configured[peer.EgressID]
		exit, err := netip.ParseAddr(peer.ExpectedExit)
		if !used[peer.EgressID] || !found || peer.Identity.Validate() != nil || route.ExitFamily.Validate() != nil || route.Port != landing.SOCKSPort || route.Address != peer.Identity.Address ||
			peer.Identity.ID == n.Source.ID || peer.Identity.PublicKey == n.Source.PublicKey || peer.Identity.Address == n.Source.Address ||
			ids[peer.Identity.ID] || keys[peer.Identity.PublicKey] || addresses[peer.Identity.Address] || err != nil || exit.String() != peer.ExpectedExit || !landing.PublicIP(exit) || !validRouteTarget(peer.Target) {
			return invalid
		}
		if route.ExitFamily == glivela.EgressIPv4Only && !exit.Is4() || route.ExitFamily == glivela.EgressIPv6Only && !exit.Is6() {
			return invalid
		}
		delete(used, peer.EgressID)
		ids[peer.Identity.ID], keys[peer.Identity.PublicKey], addresses[peer.Identity.Address] = true, true, true
	}
	if len(used) != 0 {
		return invalid
	}
	return nil
}
