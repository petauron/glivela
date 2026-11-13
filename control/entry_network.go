package control

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"

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
	RelayIdentity *landing.PeerIdentity `json:"relayIdentity,omitempty"`
	ClientChainID string                `json:"clientChainId,omitempty"`
	EgressID      string                `json:"egressId"`
	Identity      landing.PeerIdentity  `json:"identity"`
	Target        string                `json:"target"`
	ExpectedExit  string                `json:"expectedExit"`
}

func (p EntryPeer) PeerKey() string {
	if p.ClientChainID != "" {
		return p.ClientChainID
	}
	return p.EgressID
}

func (n EntryNetwork) clone() EntryNetwork {
	n.Peers = slices.Clone(n.Peers)
	for i := range n.Peers {
		if n.Peers[i].RelayIdentity != nil {
			v := *n.Peers[i].RelayIdentity
			n.Peers[i].RelayIdentity = &v
		}
	}
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
		if used[peer.PeerKey()] {
			return invalid
		}
		used[peer.PeerKey()] = true
	}
	if len(used) != len(n.Peers) {
		return invalid
	}
	configured := make(map[string]glivela.RoutePeer, len(plan.Peers))
	for _, peer := range plan.Peers {
		configured[peer.PeerKey()] = peer
	}
	ids, keys, addresses := map[string]string{}, map[string]string{}, map[string]string{}
	endpoints := map[string]bool{}
	physical := map[string]landing.PeerIdentity{}
	for _, peer := range n.Peers {
		route, found := configured[peer.PeerKey()]
		if previous, ok := physical[peer.EgressID]; ok && previous != peer.Identity {
			return invalid
		}
		physical[peer.EgressID] = peer.Identity
		if route.Relay == nil && peer.RelayIdentity != nil || route.Relay != nil && (peer.RelayIdentity == nil || peer.RelayIdentity.Validate() != nil || peer.RelayIdentity.Address == peer.Identity.Address || peer.RelayIdentity.Address == n.Source.Address || peer.RelayIdentity.ID == peer.Identity.ID || peer.RelayIdentity.ID == n.Source.ID || peer.RelayIdentity.PublicKey == peer.Identity.PublicKey || peer.RelayIdentity.PublicKey == n.Source.PublicKey) {
			return invalid
		}
		exit, err := netip.ParseAddr(peer.ExpectedExit)
		if !used[peer.PeerKey()] || !found || peer.ClientChainID != route.ClientChainID || peer.Identity.Validate() != nil || route.ExitFamily.Validate() != nil || route.Port != route.Transport.ListenerPort() || route.Address != peer.Identity.Address ||
			peer.Identity.ID == n.Source.ID || peer.Identity.PublicKey == n.Source.PublicKey || peer.Identity.Address == n.Source.Address ||
			(ids[peer.Identity.ID] != "" && ids[peer.Identity.ID] != peer.EgressID) || (keys[peer.Identity.PublicKey] != "" && keys[peer.Identity.PublicKey] != peer.EgressID) || (addresses[peer.Identity.Address] != "" && addresses[peer.Identity.Address] != peer.EgressID) || err != nil || exit.String() != peer.ExpectedExit || !landing.PublicIP(exit) || !validRouteTarget(peer.Target) {
			return invalid
		}
		if route.ExitFamily == glivela.EgressIPv4Only && !exit.Is4() || route.ExitFamily == glivela.EgressIPv6Only && !exit.Is6() {
			return invalid
		}
		dial := route.DialTransport()
		endpoint := dial.Endpoint(route.Address) + ":" + strconv.Itoa(dial.ListenerPort())
		if endpoints[endpoint] {
			return invalid
		}
		endpoints[endpoint] = true
		delete(used, peer.PeerKey())
		ids[peer.Identity.ID], keys[peer.Identity.PublicKey], addresses[peer.Identity.Address] = peer.EgressID, peer.EgressID, peer.EgressID
	}
	if len(used) != 0 {
		return invalid
	}
	return nil
}
