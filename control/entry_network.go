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
	// RelayPeers and PooledLandings decouple physical relay transport edges from
	// logical fixed-landing routes so multiple routes may share a relay:24000 socket.
	RelayPeers     []EntryRelayNetworkPeer `json:"relayPeers,omitempty"`
	PooledLandings []EntryPooledLanding    `json:"pooledLandings,omitempty"`
	// SpeedPeers authorize temporary point-to-point tests, not proxy routes.
	SpeedPeers []EntrySpeedPeer `json:"speedPeers,omitempty"`
}

type EntryRelayNetworkPeer struct {
	NodeID        string               `json:"nodeId"`
	CertificateID string               `json:"certificateId"`
	Identity      landing.PeerIdentity `json:"identity"`
}

type EntryPooledLanding struct {
	EgressID      string                `json:"egressId"`
	CertificateID string                `json:"certificateId"`
	Identity      *landing.PeerIdentity `json:"identity,omitempty"`
	ExpectedExit  string                `json:"expectedExit"`
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
	n.RelayPeers = slices.Clone(n.RelayPeers)
	n.PooledLandings = slices.Clone(n.PooledLandings)
	for i := range n.PooledLandings {
		if n.PooledLandings[i].Identity != nil {
			v := *n.PooledLandings[i].Identity
			n.PooledLandings[i].Identity = &v
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
	hasPoolNet := len(n.RelayPeers) != 0 || len(n.PooledLandings) != 0
	if len(n.Peers) > 1024 || len(n.RelayPeers) > 1024 || len(n.PooledLandings) > 1024 {
		return invalid
	}
	if len(n.Peers) == 0 && !hasPoolNet && n.Source != nil {
		return invalid
	}
	if len(n.Peers) != 0 && (n.Source == nil || n.Source.Validate() != nil) {
		return invalid
	}
	if n.Source != nil && n.Source.Validate() != nil {
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
	registerIdentity := func(nodeID string, identity landing.PeerIdentity) bool {
		if identity.Validate() != nil {
			return false
		}
		if n.Source != nil && (identity.ID == n.Source.ID || identity.PublicKey == n.Source.PublicKey || identity.Address == n.Source.Address) {
			return false
		}
		if previous, ok := physical[nodeID]; ok && previous != identity {
			return false
		}
		if ids[identity.ID] != "" && ids[identity.ID] != nodeID {
			return false
		}
		if keys[identity.PublicKey] != "" && keys[identity.PublicKey] != nodeID {
			return false
		}
		if addresses[identity.Address] != "" && addresses[identity.Address] != nodeID {
			return false
		}
		physical[nodeID] = identity
		ids[identity.ID], keys[identity.PublicKey], addresses[identity.Address] = nodeID, nodeID, nodeID
		return true
	}
	for _, peer := range n.Peers {
		route, found := configured[peer.PeerKey()]
		if !registerIdentity(peer.EgressID, peer.Identity) {
			return invalid
		}
		if route.Relay == nil && peer.RelayIdentity != nil || route.Relay != nil && (peer.RelayIdentity == nil || peer.RelayIdentity.Validate() != nil || peer.RelayIdentity.Address == peer.Identity.Address || peer.RelayIdentity.Address == n.Source.Address || peer.RelayIdentity.ID == peer.Identity.ID || peer.RelayIdentity.ID == n.Source.ID || peer.RelayIdentity.PublicKey == peer.Identity.PublicKey || peer.RelayIdentity.PublicKey == n.Source.PublicKey) {
			return invalid
		}
		exit, err := netip.ParseAddr(peer.ExpectedExit)
		if !used[peer.PeerKey()] || !found || peer.ClientChainID != route.ClientChainID || route.ExitFamily.Validate() != nil || route.Port != route.Transport.ListenerPort() || route.Address != peer.Identity.Address || err != nil || exit.String() != peer.ExpectedExit || !landing.PublicIP(exit) || !validRouteTarget(peer.Target) {
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
	}
	if len(used) != 0 {
		return invalid
	}
	relayNodes := map[string]bool{}
	for _, rp := range n.RelayPeers {
		if !glivela.ValidIdentifier(rp.NodeID) || !glivela.ValidIdentity(rp.CertificateID) || relayNodes[rp.NodeID] || !registerIdentity(rp.NodeID, rp.Identity) {
			return invalid
		}
		relayNodes[rp.NodeID] = true
	}
	pooledLandings := map[string]EntryPooledLanding{}
	for _, pl := range n.PooledLandings {
		exit, err := netip.ParseAddr(pl.ExpectedExit)
		if !glivela.ValidIdentifier(pl.EgressID) || !glivela.ValidIdentity(pl.CertificateID) || pooledLandings[pl.EgressID].EgressID != "" || err != nil || exit.String() != pl.ExpectedExit || !landing.PublicIP(exit) {
			return invalid
		}
		if pl.Identity != nil && !registerIdentity(pl.EgressID, *pl.Identity) {
			return invalid
		}
		pooledLandings[pl.EgressID] = pl
	}
	usedRelays := map[string]bool{}
	for _, edge := range plan.RelayEdges {
		if !relayNodes[edge.RelayNodeID] {
			return invalid
		}
		usedRelays[edge.RelayNodeID] = true
	}
	if len(usedRelays) != len(relayNodes) {
		return invalid
	}
	usedLandings := map[string]bool{}
	for _, pool := range plan.RelayPools {
		pl, ok := pooledLandings[pool.EgressID]
		if !ok {
			return invalid
		}
		if len(pool.Candidates) > 0 && pl.Identity == nil {
			return invalid
		}
		usedLandings[pool.EgressID] = true
		for _, cand := range pool.Candidates {
			if !relayNodes[cand.RelayNodeID] || cand.RelayNodeID == pool.EgressID {
				return invalid
			}
		}
	}
	if len(usedLandings) != len(pooledLandings) {
		return invalid
	}
	return nil
}
