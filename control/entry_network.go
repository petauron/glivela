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
	// SpeedPeers authorize temporary point-to-point tests, not proxy routes.
	SpeedPeers []EntrySpeedPeer `json:"speedPeers,omitempty"`
}

type EntrySpeedPeer struct {
	ChainID   string `json:"chainId"`
	AccountID string `json:"accountId"`
	LandingID string `json:"landingId"`
	Address   string `json:"address"`
	Source    string `json:"source"`
}

type EntryPeer struct {
	EgressID     string               `json:"egressId"`
	Identity     landing.PeerIdentity `json:"identity"`
	Target       string               `json:"target"`
	ExpectedExit string               `json:"expectedExit"`
}

func (n EntryNetwork) clone() EntryNetwork {
	n.Peers = slices.Clone(n.Peers)
	n.SpeedPeers = slices.Clone(n.SpeedPeers)
	if n.Source != nil {
		source := *n.Source
		n.Source = &source
	}
	return n
}

func (n EntryNetwork) validate(plan glivela.XrayPlan) error {
	invalid := errors.New("control: entry transport identity and routed peers differ")
	if len(n.SpeedPeers) > 1000 {
		return invalid
	}
	chains := map[string]bool{}
	for _, peer := range n.SpeedPeers {
		if !glivela.ValidIdentifier(peer.ChainID) || !glivela.ValidIdentifier(peer.AccountID) || !glivela.ValidIdentifier(peer.LandingID) || !publicSpeedAddresses(peer.Address, peer.Source) || chains[peer.ChainID] {
			return invalid
		}
		chains[peer.ChainID] = true
		if !slices.ContainsFunc(plan.Credentials, func(c glivela.CredentialMaterial) bool {
			return c.Credential.Kind == glivela.NativeCredential && c.Credential.AccountID == peer.AccountID && c.Credential.EntryID != peer.LandingID
		}) {
			return invalid
		}
	}
	if len(n.Peers) > 1024 || len(n.Peers) == 0 && n.Source != nil || len(n.Peers) != 0 && (n.Source == nil || n.Source.Validate() != nil) {
		return invalid
	}
	used := make(map[string]bool)
	// Explicitly enrolled transports may precede the first account grant.
	// Xray still requires every grant to reference one of these exact peers;
	// enrollment alone does not create an inbound credential or route rule.
	for _, peer := range plan.Peers {
		if used[peer.EgressID] {
			return invalid
		}
		used[peer.EgressID] = true
	}
	if len(used) != len(n.Peers) {
		return invalid
	}
	configured := make(map[string]glivela.RoutePeer, len(plan.Peers))
	for _, peer := range plan.Peers {
		configured[peer.EgressID] = peer
	}
	ids, keys, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	endpoints := map[string]bool{}
	for _, peer := range n.Peers {
		route, found := configured[peer.EgressID]
		exit, err := netip.ParseAddr(peer.ExpectedExit)
		if !used[peer.EgressID] || !found || peer.Identity.Validate() != nil || route.ExitFamily.Validate() != nil || route.Port != route.Transport.ListenerPort() || route.Address != peer.Identity.Address ||
			peer.Identity.ID == n.Source.ID || peer.Identity.PublicKey == n.Source.PublicKey || peer.Identity.Address == n.Source.Address ||
			ids[peer.Identity.ID] || keys[peer.Identity.PublicKey] || addresses[peer.Identity.Address] || err != nil || exit.String() != peer.ExpectedExit || !landing.PublicIP(exit) || !validRouteTarget(peer.Target) {
			return invalid
		}
		if route.ExitFamily == glivela.EgressIPv4Only && !exit.Is4() || route.ExitFamily == glivela.EgressIPv6Only && !exit.Is6() {
			return invalid
		}
		endpoint := route.Transport.Endpoint(route.Address)
		if endpoints[endpoint] {
			return invalid
		}
		endpoints[endpoint] = true
		delete(used, peer.EgressID)
		ids[peer.Identity.ID], keys[peer.Identity.PublicKey], addresses[peer.Identity.Address] = true, true, true
	}
	if len(used) != 0 {
		return invalid
	}
	return nil
}
