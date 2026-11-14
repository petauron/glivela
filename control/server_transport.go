package control

import (
	"errors"
	"reflect"
	"slices"
	"sort"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func (s *Store) boundServerTransport(entry Node, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	if s.business == nil {
		return glivela.ServerTransport{}, false
	}
	return boundServerTransportIn(s.nodes, s.business.material, entry, target, peer)
}

// Runtime authorization consults only server-owned resources. Client
// publication records and shared client-credential maps have no authority here.
func serverTransportIdentity(nodes map[string]Node, r glivela.ServerTransport, entry, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	if r.Validate() != nil || r.EntryID != entry.ID || r.EgressID != target.ID || r.EntryCertificateID != entry.CertificateID || r.LandingCertificateID != target.CertificateID || !reflect.DeepEqual(r.Peer, peer) || entry.Desired.Entry == nil || target.Desired.Landing == nil || peer.Address != target.Desired.Landing.Address {
		return glivela.ServerTransport{}, false
	}
	if r.Peer.Relay != nil {
		found := false
		for _, n := range nodes {
			if n.ID == r.Peer.Relay.NodeID && n.CertificateID == r.Peer.Relay.CertificateID && n.Desired.Landing != nil {
				found = true
			}
		}
		if !found {
			return glivela.ServerTransport{}, false
		}
	}
	return r, true
}

func boundServerTransportIn(nodes map[string]Node, m glivela.ImportMaterial, entry, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	r, found := m.ServerTransports[peer.Transport.ClientListenerID]
	if !found {
		return glivela.ServerTransport{}, false
	}
	if _, ok := serverTransportIdentity(nodes, r, entry, target, peer); !ok || entry.Desired.EntryNetwork == nil || !slices.Contains(target.Desired.Landing.ClientListeners, r.Listener) {
		return glivela.ServerTransport{}, false
	}
	if !slices.ContainsFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool { return p.PeerKey() == peer.PeerKey() && p.ExpectedExit == r.ExpectedExit }) {
		return glivela.ServerTransport{}, false
	}
	if r.Peer.Relay != nil {
		found := false
		for _, node := range nodes {
			if node.ID == r.Peer.Relay.NodeID && node.Desired.Landing != nil && slices.Contains(node.Desired.Landing.ClientListeners, *r.RelayListener) {
				found = true
			}
		}
		if !found {
			return glivela.ServerTransport{}, false
		}
	}
	return r, true
}

// Explicit server-route activation may restore its already-owned listener;
// publication and node startup still require the fully applied binding above.
func (s *Store) configuredServerTransport(entry, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	if s.business == nil {
		return glivela.ServerTransport{}, false
	}
	return configuredServerTransportIn(s.nodes, s.business.material, entry, target, peer)
}

func configuredServerTransportIn(nodes map[string]Node, material glivela.ImportMaterial, entry, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	r, ok := material.ServerTransports[peer.Transport.ClientListenerID]
	if !ok || entry.Desired.EntryNetwork == nil || !slices.ContainsFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool { return p.PeerKey() == peer.PeerKey() && p.ExpectedExit == r.ExpectedExit }) {
		return glivela.ServerTransport{}, false
	}
	return serverTransportIdentity(nodes, r, entry, target, peer)
}

// Validate ownership before projection can interpret a missing/mismatched peer
// as permission to withdraw sockets. This applies equally to two and three hops.
func validateServerTransportBindings(nodes map[string]Node, material glivela.ImportMaterial) error {
	if material.ServerTransportVersion != 1 {
		return nil
	}
	bad := errors.New("control: server transport configuration differs from owned identity")
	byID := make(map[string]Node, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	for _, entry := range nodes {
		if entry.Desired.Entry == nil || entryRetired(material, entry.ID) {
			continue
		}
		for _, peer := range entry.Desired.Entry.Peers {
			if peer.Transport.ClientListenerID != "" {
				if _, ok := configuredServerTransportIn(nodes, material, entry, byID[peer.EgressID], peer); !ok {
					return bad
				}
			}
		}
	}
	for _, r := range material.ServerTransports {
		entry, target := byID[r.EntryID], byID[r.EgressID]
		if _, ok := serverTransportIdentity(nodes, r, entry, target, r.Peer); !ok {
			return bad
		}
		present := false
		for _, peer := range entry.Desired.Entry.Peers {
			if peer.PeerKey() == r.Peer.PeerKey() {
				if _, ok := configuredServerTransportIn(nodes, material, entry, target, peer); !ok || !reflect.DeepEqual(peer, r.Peer) {
					return bad
				}
				present = true
			}
		}
		if present {
			continue
		}
		for _, account := range material.Plan.Accounts {
			for _, g := range account.Grants {
				if !material.DeletedRoutes[g.ID] && g.AccountID == r.AccountID && g.EntryID == r.EntryID && g.EgressID == r.EgressID && g.ClientChainID == r.Peer.ClientChainID && g.Enabled {
					return bad
				}
			}
		}
	}
	return nil
}

func serverOwnsListener(m glivela.ImportMaterial, id string) bool {
	_, ok := m.ServerTransports[id]
	return ok
}

func appendServerListeners(nodes map[string]Node, wanted map[string][]landing.ClientListener, r glivela.ServerTransport) error {
	bad := errors.New("control: owned server listener identity differs")
	targetFound, entryFound, relayFound := false, false, r.Peer.Relay == nil
	for _, n := range nodes {
		if n.ID == r.EntryID && n.CertificateID == r.EntryCertificateID && n.Desired.Entry != nil {
			entryFound = true
		}
		if n.ID == r.EgressID && n.CertificateID == r.LandingCertificateID && n.Desired.Landing != nil {
			targetFound = true
		}
		if r.Peer.Relay != nil && n.ID == r.Peer.Relay.NodeID && n.CertificateID == r.Peer.Relay.CertificateID && n.Desired.Landing != nil {
			relayFound = true
		}
	}
	if r.Validate() != nil || !entryFound || !targetFound || !relayFound {
		return bad
	}
	wanted[r.EgressID] = append(wanted[r.EgressID], r.Listener)
	if r.Peer.Relay != nil {
		wanted[r.Peer.Relay.NodeID] = append(wanted[r.Peer.Relay.NodeID], *r.RelayListener)
	}
	return nil
}

// Preserve existing deterministic order when ownership moves, without treating
// an existing runtime's contents as authority for any new or changed listener.
func orderedTransportListeners(current, candidates []landing.ClientListener) ([]landing.ClientListener, error) {
	byID := map[string]landing.ClientListener{}
	for _, listener := range candidates {
		if old, ok := byID[listener.ID]; ok && old != listener {
			return nil, errors.New("control: conflicting listener ownership")
		}
		byID[listener.ID] = listener
	}
	var out []landing.ClientListener
	for _, old := range current {
		if listener, ok := byID[old.ID]; ok {
			out = append(out, listener)
			delete(byID, old.ID)
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out, nil
}

func serverTransportUsed(nodes map[string]Node, m glivela.ImportMaterial, r glivela.ServerTransport, grants map[string]glivela.RouteGrant) bool {
	for _, node := range nodes {
		if node.ID != r.EntryID || node.Desired.Entry == nil {
			continue
		}
		if !slices.ContainsFunc(node.Desired.Entry.Peers, func(p glivela.RoutePeer) bool { return reflect.DeepEqual(p, r.Peer) }) {
			continue
		}
		for _, current := range node.Desired.Entry.Grants {
			g, ok := grants[current.ID]
			if ok && !m.DeletedRoutes[g.ID] && g.AccountID == r.AccountID && g.EntryID == r.EntryID && g.EgressID == r.EgressID && g.ClientChainID == r.Peer.ClientChainID && g.Enabled && g.Route.Enabled {
				return true
			}
		}
	}
	return false
}
