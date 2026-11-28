package control

import (
	"errors"
	"math"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func (s *Store) boundServerTransport(entry Node, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	if s.business == nil {
		return glivela.ServerTransport{}, false
	}
	return boundServerTransportIn(s.nodes, s.business.material, entry, target, peer)
}

func isPendingLegacyThreeHop(m glivela.ImportMaterial, transportID string) bool {
	if transportID == "" {
		return false
	}
	for _, pr := range m.PooledRoutes {
		if !m.DeletedRoutes[pr.GrantID] && pr.PendingLegacyCutover && pr.LegacyTransportID == transportID {
			return true
		}
	}
	return false
}

// isRetainedLegacyThreeHop reports whether a migrated legacy single-relay
// ServerTransport must remain projected on relay/landing until either its
// explicit cutover is triggered OR every cut-over entry referencing it has
// reported a fresh applied receipt for its new RelayPool configuration.
func isRetainedLegacyThreeHop(nodes map[string]Node, m glivela.ImportMaterial, transportID string, now time.Time) bool {
	if transportID == "" {
		return false
	}
	if isPendingLegacyThreeHop(m, transportID) {
		return true
	}
	for _, pr := range m.PooledRoutes {
		if m.DeletedRoutes[pr.GrantID] || !pr.RetiringLegacyTransport || pr.LegacyTransportID != transportID {
			continue
		}
		entryApplied := false
		for _, n := range nodes {
			if n.ID != pr.EntryID || n.Desired.Entry == nil {
				continue
			}
			hasLegacyPeer := slices.ContainsFunc(n.Desired.Entry.Peers, func(p glivela.RoutePeer) bool {
				return p.Relay != nil && p.Transport.ClientListenerID == transportID
			})
			hasPooledGrant := slices.ContainsFunc(n.Desired.Entry.Grants, func(g glivela.RouteGrant) bool {
				return g.ID == pr.GrantID && g.RelayPoolID == pr.RelayPoolID && g.ClientChainID == ""
			})
			if !hasLegacyPeer && hasPooledGrant && runtimeFresh(n, now) {
				entryApplied = true
			}
			break
		}
		if !entryApplied {
			return true
		}
	}
	return false
}

// Runtime authorization consults only server-owned resources. Client
// publication records and shared client-credential maps have no authority here.
// Three-hop forwarding is served through RelayPools in v2; legacy single-relay
// transports remain readable only while awaiting explicit cutover or entry receipt.
func serverTransportIdentity(nodes map[string]Node, m glivela.ImportMaterial, r glivela.ServerTransport, entry, target Node, peer glivela.RoutePeer) (glivela.ServerTransport, bool) {
	if r.Validate() != nil || r.EntryID != entry.ID || r.EgressID != target.ID || r.EntryCertificateID != entry.CertificateID || r.LandingCertificateID != target.CertificateID || !reflect.DeepEqual(r.Peer, peer) || entry.Desired.Entry == nil || target.Desired.Landing == nil || peer.Address != target.Desired.Landing.Address {
		return glivela.ServerTransport{}, false
	}
	if r.Peer.Relay != nil || r.RelayListener != nil {
		if m.ServerTransportVersion == glivela.CurrentServerTransportVersion && !isRetainedLegacyThreeHop(nodes, m, r.ID, time.Now().UTC()) {
			return glivela.ServerTransport{}, false
		}
		if r.Peer.Relay == nil || r.RelayListener == nil {
			return glivela.ServerTransport{}, false
		}
		relay, ok := nodes[r.Peer.Relay.CertificateID]
		if !ok || relay.ID != r.Peer.Relay.NodeID || relay.Desired.Landing == nil {
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
	if _, ok := serverTransportIdentity(nodes, m, r, entry, target, peer); !ok || entry.Desired.EntryNetwork == nil {
		return glivela.ServerTransport{}, false
	}
	if !slices.ContainsFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool { return p.PeerKey() == peer.PeerKey() && p.ExpectedExit == r.ExpectedExit }) {
		return glivela.ServerTransport{}, false
	}
	if r.Peer.Relay != nil {
		relay := nodes[r.Peer.Relay.CertificateID]
		if relay.Desired.Landing == nil || !slices.Contains(relay.Desired.Landing.ClientListeners, *r.RelayListener) {
			return glivela.ServerTransport{}, false
		}
	}
	if strings.Contains(r.Peer.Transport.Key, ":") {
		serverKey, userKey, ok := strings.Cut(r.Peer.Transport.Key, ":")
		if !ok {
			return glivela.ServerTransport{}, false
		}
		matched := false
		for _, l := range target.Desired.Landing.EIHListeners {
			if l.Address != r.Peer.Transport.PublicAddress || l.Port != glivela.RelayPoolPort || l.ServerKey != serverKey {
				continue
			}
			for _, u := range l.Users {
				if u.Role == "landing" && u.Key == userKey && u.Source == r.Listener.Source {
					matched = true
					break
				}
			}
		}
		if !matched {
			return glivela.ServerTransport{}, false
		}
		return r, true
	}
	if !slices.Contains(target.Desired.Landing.ClientListeners, r.Listener) {
		return glivela.ServerTransport{}, false
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
	return serverTransportIdentity(nodes, material, r, entry, target, peer)
}

// Validate ownership before projection can interpret a missing/mismatched peer
// as permission to withdraw sockets. Two-hop ServerTransports and any pending
// legacy three-hop cutover bindings are checked here.
func validateServerTransportBindings(nodes map[string]Node, material glivela.ImportMaterial) error {
	if material.ServerTransportVersion == 0 {
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
			if peer.Relay != nil && !isPendingLegacyThreeHop(material, peer.Transport.ClientListenerID) {
				// Retired single-relay peers after explicit cutover are cleared by projectRelayPools.
				continue
			}
			if peer.Transport.ClientListenerID != "" {
				if _, ok := configuredServerTransportIn(nodes, material, entry, byID[peer.EgressID], peer); !ok {
					return bad
				}
			}
		}
	}
	for _, r := range material.ServerTransports {
		entry, target := byID[r.EntryID], byID[r.EgressID]
		if _, ok := serverTransportIdentity(nodes, material, r, entry, target, r.Peer); !ok {
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

func appendServerListeners(nodes map[string]Node, m glivela.ImportMaterial, wanted map[string][]landing.ClientListener, r glivela.ServerTransport, now time.Time, cutovers map[string]SocketCutover) error {
	bad := errors.New("control: owned server listener identity differs")
	targetFound, entryFound := false, false
	var targetNode Node
	for _, n := range nodes {
		if n.ID == r.EntryID && n.CertificateID == r.EntryCertificateID && n.Desired.Entry != nil {
			entryFound = true
		}
		if n.ID == r.EgressID && n.CertificateID == r.LandingCertificateID && n.Desired.Landing != nil {
			targetFound, targetNode = true, n
		}
	}
	if r.Validate() != nil || !entryFound || !targetFound {
		return bad
	}
	if r.Peer.Relay != nil || r.RelayListener != nil {
		if m.ServerTransportVersion == glivela.CurrentServerTransportVersion && !isRetainedLegacyThreeHop(nodes, m, r.ID, now) {
			return bad
		}
		if r.Peer.Relay == nil || r.RelayListener == nil {
			return bad
		}
		relay, ok := nodes[r.Peer.Relay.CertificateID]
		if !ok || relay.ID != r.Peer.Relay.NodeID || relay.Desired.Landing == nil {
			return bad
		}
		relayAddr := relay.Desired.Landing.Transport.PublicAddress
		if r.RelayListener.Transport == "ipv6-ss2022" || r.RelayListener.Interface != "" {
			relayAddr = r.RelayListener.Address
		}
		if r.RelayListener.Port != glivela.RelayPoolPort || !cutoverOwnsSocket(cutovers, relay.ID, relayAddr) {
			wanted[relay.ID] = append(wanted[relay.ID], *r.RelayListener)
		}
	}
	if strings.Contains(r.Peer.Transport.Key, ":") {
		// Cut-over landing EIH sockets are rendered via Plan.EIHListeners, while
		// any legacy RelayListener above remains projected until retired.
		return nil
	}
	targetAddr := targetNode.Desired.Landing.Transport.PublicAddress
	if r.Listener.Transport == "ipv6-ss2022" || r.Listener.Interface != "" {
		targetAddr = r.Listener.Address
	}
	if r.Listener.Port == glivela.RelayPoolPort && cutoverOwnsSocket(cutovers, r.EgressID, targetAddr) {
		return nil
	}
	wanted[r.EgressID] = append(wanted[r.EgressID], r.Listener)
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

func serverTransportUsed(nodes map[string]Node, m glivela.ImportMaterial, r glivela.ServerTransport, grants map[string]glivela.RouteGrant, now time.Time) bool {
	if r.Peer.Relay != nil && isRetainedLegacyThreeHop(nodes, m, r.ID, now) {
		for _, g := range grants {
			if !m.DeletedRoutes[g.ID] && g.AccountID == r.AccountID && g.EntryID == r.EntryID && g.EgressID == r.EgressID && g.Enabled && g.Route.Enabled && (g.ClientChainID == r.Peer.ClientChainID || g.RelayPoolID != "" && m.PooledRoutes[g.ID].LegacyTransportID == r.ID) {
				return true
			}
		}
		return false
	}
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

func projectServerLandings(nodes map[string]Node, m glivela.ImportMaterial, now time.Time, cutovers map[string]SocketCutover) (bool, error) {
	if err := validateServerTransportBindings(nodes, m); err != nil {
		return false, err
	}
	_, serverGrants, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return false, err
	}
	wanted := map[string][]landing.ClientListener{}
	for _, resource := range m.ServerTransports {
		if !serverTransportUsed(nodes, m, resource, serverGrants, now) {
			continue
		}
		if err := appendServerListeners(nodes, m, wanted, resource, now, cutovers); err != nil {
			return false, err
		}
	}
	udpListeners, udpSources, err := routeUDPLandings(nodes, m, serverGrants, now, cutovers)
	if err != nil {
		return false, err
	}
	changed := false
	for cert, n := range nodes {
		if n.Desired.Landing == nil {
			continue
		}
		plan := *n.Desired.Landing
		plan.Sources = slices.Clone(plan.Sources)
		if len(plan.Sources) == 0 {
			plan.Sources = nil
		}
		for i := range plan.Sources {
			plan.Sources[i].UDPOverTCP = slices.Contains(udpSources[n.ID], plan.Sources[i].Address)
		}
		listeners, err := orderedTransportListeners(plan.ClientListeners, wanted[n.ID])
		if err != nil {
			return false, err
		}
		plan.ClientListeners = listeners
		plan.UDPOverTCPListeners = udpListeners[n.ID]
		if reflect.DeepEqual(plan, *n.Desired.Landing) {
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return false, errors.New("control: landing revision exhausted")
		}
		plan.Revision++
		desired, err := NewDesired(plan)
		if err != nil {
			return false, err
		}
		n.Desired, n.Receipt, n.ReportedAt = desired, nil, time.Time{}
		n.Checks = nil
		nodes[cert] = n
		changed = true
	}
	return changed, nil
}

// Datagrams reuse existing SS2022 TCP ownership. This grants neither a new
// source nor a public UDP socket, and never changes transport keys or ports.
func routeUDPLandings(nodes map[string]Node, m glivela.ImportMaterial, grants map[string]glivela.RouteGrant, now time.Time, cutovers map[string]SocketCutover) (map[string][]string, map[string][]string, error) {
	listeners, sources := map[string][]string{}, map[string][]string{}
	byID := map[string]Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	for _, g := range grants {
		if !g.UDP || !g.Enabled || !g.Route.Enabled || m.DeletedRoutes[g.ID] {
			continue
		}
		if g.RelayPoolID != "" {
			// Retain live UDP permission on a single-user legacy three-hop
			// listener while the cut-over entry has not yet confirmed receipt.
			if pr, ok := m.PooledRoutes[g.ID]; ok && pr.RetiringLegacyTransport && isRetainedLegacyThreeHop(nodes, m, pr.LegacyTransportID, now) {
				if r, hasR := m.ServerTransports[pr.LegacyTransportID]; hasR && !strings.Contains(r.Peer.Transport.Key, ":") {
					target := byID[r.EgressID]
					if target.Desired.Landing != nil {
						targetAddr := target.Desired.Landing.Transport.PublicAddress
						if r.Listener.Transport == "ipv6-ss2022" || r.Listener.Interface != "" {
							targetAddr = r.Listener.Address
						}
						if !(r.Listener.Port == glivela.RelayPoolPort && cutoverOwnsSocket(cutovers, r.EgressID, targetAddr)) {
							listeners[r.EgressID] = append(listeners[r.EgressID], r.Listener.ID)
						}
					}
				}
			}
			continue
		}
		entry := byID[g.EntryID]
		if entry.Desired.Entry == nil || entry.Desired.EntryNetwork == nil {
			return nil, nil, errors.New("control: UDP entry is not enrolled")
		}
		keys := []string{g.PeerKey()}
		if g.IPv4EgressID != "" {
			keys = append(keys, g.IPv4EgressID)
		}
		for _, key := range keys {
			i := slices.IndexFunc(entry.Desired.Entry.Peers, func(p glivela.RoutePeer) bool { return p.PeerKey() == key })
			if i < 0 {
				return nil, nil, errors.New("control: UDP requires an existing peer")
			}
			p := entry.Desired.Entry.Peers[i]
			target := byID[p.EgressID]
			if p.Transport.Protocol != "ss2022" || target.Desired.Landing == nil {
				return nil, nil, errors.New("control: UDP-over-TCP requires an enrolled SS2022 landing")
			}
			if strings.Contains(p.Transport.Key, ":") {
				continue // Cut-over two-hop or legacy-landing EIH UDP policy is owned by TwoHopEIHBindings.
			}
			// Check the final landing socket (p.Transport), NOT p.DialTransport()
			// which points to the relay hop on legacy three-hop peers.
			if p.Transport.ListenerPort() == glivela.RelayPoolPort && cutoverOwnsSocket(cutovers, target.ID, p.Transport.Endpoint(p.Address)) {
				continue // Active Option A cutover owns this socket's EIH listener and UDP grant.
			}
			if p.Transport.ClientListenerID != "" {
				r, ok := configuredServerTransportIn(nodes, m, entry, target, p)
				if !ok || r.AccountID != g.AccountID {
					return nil, nil, errors.New("control: UDP listener ownership differs")
				}
				listeners[target.ID] = append(listeners[target.ID], r.Listener.ID)
			} else {
				if entry.Desired.EntryNetwork.Source == nil || p.Transport != target.Desired.Landing.Transport {
					return nil, nil, errors.New("control: UDP source transport differs")
				}
				address := entry.Desired.EntryNetwork.Source.Address
				if !slices.ContainsFunc(target.Desired.Landing.Sources, func(s landing.Source) bool { return s.Address == address && s.TCPOnly }) {
					return nil, nil, errors.New("control: UDP requires an existing exact TCP source")
				}
				sources[target.ID] = append(sources[target.ID], address)
			}
		}
	}
	for _, set := range []map[string][]string{listeners, sources} {
		for id, values := range set {
			slices.SortFunc(values, strings.Compare)
			set[id] = slices.Compact(values)
		}
	}
	return listeners, sources, nil
}
