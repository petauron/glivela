package control

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// This is a one-way ownership migration, not a runtime lookup fallback. Only
// authenticated, exactly matched policies may cross the ownership boundary.
func migrateServerTransports(nodes map[string]Node, original glivela.ImportMaterial) (glivela.ImportMaterial, bool, error) {
	if original.ServerTransportVersion == glivela.CurrentServerTransportVersion {
		return original, false, nil
	}
	if original.ServerTransportVersion > glivela.CurrentServerTransportVersion {
		return original, false, errors.New("control: unknown server transport schema")
	}
	current := original
	changed := false
	if current.ServerTransportVersion == 0 {
		v1, v1Changed, err := migrateServerTransportsV0ToV1(nodes, current)
		if err != nil {
			return original, false, err
		}
		current, changed = v1, changed || v1Changed
	}
	if current.ServerTransportVersion == 1 {
		v2, v2Changed, err := migrateServerTransportsV1ToV2(nodes, current)
		if err != nil {
			return original, false, err
		}
		current, changed = v2, changed || v2Changed
	}
	return current, changed, nil
}

func migrateServerTransportsV0ToV1(nodes map[string]Node, original glivela.ImportMaterial) (glivela.ImportMaterial, bool, error) {
	_, grants, err := effectiveBusinessCredentials(original, time.Now())
	if err != nil {
		return original, false, err
	}
	next := original
	next.ServerTransportVersion = 1
	next.ServerTransports = nil
	for _, entry := range nodes {
		if entry.Desired.Entry == nil {
			continue
		}
		for _, peer := range entry.Desired.Entry.Peers {
			if peer.Transport.ClientListenerID == "" {
				continue
			}
			var target Node
			for _, n := range nodes {
				if n.ID == peer.EgressID {
					target = n
				}
			}
			c, ok := migrationClientBinding(nodes, original, entry, target, peer, grants)
			if !ok {
				return original, false, errors.New("control: server transport ownership migration requires exact enrolled binding")
			}
			r := glivela.ServerTransport{ID: c.ID, Name: c.Name, AccountID: c.AccountID, EntryID: entry.ID, EgressID: target.ID, EntryCertificateID: entry.CertificateID, LandingCertificateID: target.CertificateID, Peer: peer}
			_, source, err := chainLanding(nodes, c)
			if err != nil {
				return original, false, err
			}
			r.Listener = clientListener(c, source)
			for _, p := range entry.Desired.EntryNetwork.Peers {
				if p.PeerKey() == peer.PeerKey() {
					r.ExpectedExit = p.ExpectedExit
				}
			}
			if peer.Relay != nil {
				listener := clientRelayListener(c)
				r.RelayListener = &listener
			}
			if r.Validate() != nil {
				return original, false, errors.New("control: invalid captured server transport")
			}
			raw, err := json.Marshal(r)
			if err != nil {
				return original, false, err
			}
			if err = json.Unmarshal(raw, &r); err != nil {
				return original, false, err
			}
			if existing, ok := next.ServerTransports[r.ID]; ok && !reflect.DeepEqual(existing, r) {
				return original, false, errors.New("control: conflicting server transport owners")
			}
			if next.ServerTransports == nil {
				next.ServerTransports = map[string]glivela.ServerTransport{}
			}
			next.ServerTransports[r.ID] = r
		}
	}
	if err := migrateNativeServerLandings(nodes, original, &next); err != nil {
		return original, false, err
	}
	if err := next.Validate(); err != nil {
		return original, false, err
	}
	return next, true, nil
}

// migrateServerTransportsV1ToV2 performs a forward-only schema upgrade that
// creates size=1 RelayPools and PendingLegacyCutover PooledRoutes for legacy
// single-relay three-hop ServerTransports WITHOUT withdrawing the running old
// three-hop path at controller startup. Switching the live entry grant happens
// only via explicit CutoverLegacyPooledRoute once downstream EIH 24000 receipts
// confirm readiness, keeping existing traffic live if a relay is offline or
// port 24000 is still occupied.
func migrateServerTransportsV1ToV2(nodes map[string]Node, original glivela.ImportMaterial) (glivela.ImportMaterial, bool, error) {
	next := original
	next.ServerTransportVersion = glivela.CurrentServerTransportVersion
	next.ServerTransports = maps.Clone(original.ServerTransports)
	legacyThreeHop := map[string]glivela.ServerTransport{}
	legacyIDs := []string{}
	for id, r := range original.ServerTransports {
		if r.Peer.Relay != nil || r.RelayListener != nil {
			legacyThreeHop[id] = r
			legacyIDs = append(legacyIDs, id)
		}
	}
	if len(legacyIDs) == 0 {
		if err := next.Validate(); err != nil {
			return original, false, err
		}
		return next, true, nil
	}
	slices.Sort(legacyIDs)
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	next.RelayPools = maps.Clone(original.RelayPools)
	if next.RelayPools == nil {
		next.RelayPools = map[string]glivela.RelayPool{}
	}
	next.PooledRoutes = maps.Clone(original.PooledRoutes)
	if next.PooledRoutes == nil {
		next.PooledRoutes = map[string]glivela.PooledRoute{}
	}
	next.EntryRelayConfigs = maps.Clone(original.EntryRelayConfigs)
	if next.EntryRelayConfigs == nil {
		next.EntryRelayConfigs = map[string]glivela.EntryRelayConfig{}
	}

	// Build one size=1 RelayPool per distinct legacy relay node.
	poolByRelay := map[string]string{}
	for _, id := range legacyIDs {
		r := legacyThreeHop[id]
		if r.Peer.Relay == nil {
			continue
		}
		relay := r.Peer.Relay
		poolID := "pool-" + relay.NodeID
		pool, exists := next.RelayPools[poolID]
		if !exists {
			pool = glivela.RelayPool{
				ID:       poolID,
				Name:     relay.NodeID,
				Revision: 1,
				Strategy: glivela.DefaultRelayPoolStrategy(1),
				Members: []glivela.RelayPoolMember{{
					NodeID:        relay.NodeID,
					CertificateID: relay.CertificateID,
				}},
			}
		}
		member := &pool.Members[0]
		if member.CertificateID != relay.CertificateID {
			return original, false, errors.New("control: conflicting relay certificate during v2 migration")
		}
		if relay.Transport == glivela.IPv4RelaySS2022 {
			member.IngressIPv4 = relay.ServerIPv4
		} else {
			member.IngressIPv6 = relay.ServerIPv6
		}
		if r.Listener.Transport == "ipv6-ss2022" {
			member.EgressIPv6 = r.Listener.Source
		} else if glivela.PublicTransportIPv4(r.Listener.Source) {
			member.EgressIPv4 = r.Listener.Source
		}
		if relayNode, ok := byID[relay.NodeID]; ok && relayNode.Desired.Landing != nil {
			if member.EgressIPv6 == "" && glivela.PublicTransportIPv6(relayNode.Desired.Landing.EgressIP) {
				member.EgressIPv6 = relayNode.Desired.Landing.EgressIP
			}
			if member.EgressIPv4 == "" && glivela.PublicTransportIPv4(relayNode.Desired.Landing.EgressIP) {
				member.EgressIPv4 = relayNode.Desired.Landing.EgressIP
			}
		}
		next.RelayPools[poolID] = pool
		poolByRelay[relay.NodeID] = poolID

		cfg := next.EntryRelayConfigs[r.EntryID]
		if relay.Transport == glivela.IPv4RelaySS2022 && relay.SourceIPv4 != "" {
			cfg.SourceIPv4 = relay.SourceIPv4
		} else if relay.SourceIPv6 != "" {
			cfg.SourceIPv6 = relay.SourceIPv6
		}
		if cfg.Observatory == nil {
			obs := glivela.DefaultObservatoryConfig()
			cfg.Observatory = &obs
		}
		next.EntryRelayConfigs[r.EntryID] = cfg
	}

	// Stage a PendingLegacyCutover PooledRoute for every active legacy three-hop
	// grant while retaining its live ClientChainID and ServerTransport until
	// explicit cutover confirms downstream EIH 24000 receipts.
	usedLegacy := map[string]bool{}
	for _, account := range next.Plan.Accounts {
		for _, g := range account.Grants {
			if next.DeletedRoutes[g.ID] || g.ClientChainID == "" {
				continue
			}
			r, ok := legacyThreeHop[g.ClientChainID]
			if !ok || r.Peer.Relay == nil {
				return original, false, errors.New("control: legacy three-hop grant missing server transport during v2 migration")
			}
			usedLegacy[r.ID] = true
			poolID := poolByRelay[r.Peer.Relay.NodeID]
			landingAddr := r.Peer.Transport.PublicAddress
			if landingAddr == "" {
				landingAddr = r.Listener.Address
			}
			ingressFamily := "ipv6"
			if r.Peer.Relay.Transport == glivela.IPv4RelaySS2022 {
				ingressFamily = "ipv4"
			}
			next.PooledRoutes[g.ID] = glivela.PooledRoute{
				GrantID:              g.ID,
				AccountID:            g.AccountID,
				EntryID:              g.EntryID,
				EgressID:             g.EgressID,
				RelayPoolID:          poolID,
				LandingCertificateID: r.LandingCertificateID,
				LandingAddress:       landingAddr,
				ExpectedExit:         r.ExpectedExit,
				EgressIP:             r.Listener.EgressIP,
				IngressFamily:        ingressFamily,
				Name:                 r.Name,
				LegacyTransportID:    r.ID,
				PendingLegacyCutover: true,
			}
		}
	}
	// Remove idle legacy three-hop transports that have no active grant referencing them.
	for _, id := range legacyIDs {
		if !usedLegacy[id] {
			delete(next.ServerTransports, id)
		}
	}
	if len(next.ServerTransports) == 0 {
		next.ServerTransports = nil
	}
	if err := ensurePooledRouteCredentials(nodes, &next); err != nil {
		return original, false, err
	}
	if err := next.Validate(); err != nil {
		return original, false, err
	}
	return next, true, nil
}

func migrationClientBinding(nodes map[string]Node, material glivela.ImportMaterial, entry, target Node, route glivela.RoutePeer, grants map[string]glivela.RouteGrant) (glivela.ClientChain, bool) {
	if target.Desired.Landing == nil {
		return glivela.ClientChain{}, false
	}
	for _, original := range material.ClientChains {
		if original.ID != route.Transport.ClientListenerID {
			continue
		}
		c, err := material.EffectiveClientChain(original)
		if err != nil || !reflect.DeepEqual(c.Relay, route.Relay) || (c.Relay != nil && route.ClientChainID != c.ID) || (c.Relay == nil && route.ClientChainID != "") || c.EntryID != entry.ID || c.EgressID != target.ID || c.Transport == "ipv6-ss2022" && (c.EntryCertificateID != entry.CertificateID || c.LandingCertificateID != target.CertificateID) || c.Transport != "ipv6-ss2022" && c.Transport != glivela.IPv4ClientSS2022 {
			return glivela.ClientChain{}, false
		}
		n, source, err := chainLanding(nodes, c)
		if err != nil || n.ID != target.ID {
			return glivela.ClientChain{}, false
		}
		// A stopped or quota-gated route may have legitimately withdrawn its
		// socket. Capture its authenticated policy, never invent an active bind.
		allowAbsent := true
		for _, g := range grants {
			if !material.DeletedRoutes[g.ID] && g.AccountID == c.AccountID && g.EntryID == c.EntryID && g.EgressID == c.EgressID && g.ClientChainID == route.ClientChainID && g.Enabled && g.Route.Enabled {
				allowAbsent = false
			}
		}
		if c.Relay != nil {
			relay, err := chainRelay(nodes, c)
			if err != nil || !migrationListenerMatches(relay.Desired.Landing.ClientListeners, clientRelayListener(c), allowAbsent) {
				return glivela.ClientChain{}, false
			}
		}
		listener := clientListener(c, source)
		expectedExit := c.EgressIP
		if expectedExit == "" {
			expectedExit = target.Desired.Landing.EgressIP
		}
		if entry.Desired.EntryNetwork == nil || !slices.ContainsFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool { return p.PeerKey() == route.PeerKey() && p.ExpectedExit == expectedExit }) {
			return glivela.ClientChain{}, false
		}

		address := target.Desired.Landing.Transport.PublicAddress
		if c.Transport == "ipv6-ss2022" {
			address = c.ServerIPv6
		}
		if c.PrivateLink != nil {
			address = c.PrivateLink.Address
		}
		if !reflect.DeepEqual(route.Transport.PrivateLink, c.PrivateLink) || route.Transport.PublicAddress != address || route.Transport.Key != c.Key || route.Port != c.Port || route.Transport.ListenerPort() != c.Port || !migrationListenerMatches(target.Desired.Landing.ClientListeners, listener, allowAbsent) {
			return glivela.ClientChain{}, false
		}
		return c, true
	}
	return glivela.ClientChain{}, false
}

// Absence is allowed only for an inactive server path. A same-ID mismatch is
// always an ownership error, including on stopped paths.
func migrationListenerMatches(listeners []landing.ClientListener, expected landing.ClientListener, allowAbsent bool) bool {
	for _, actual := range listeners {
		if actual.ID == expected.ID {
			return actual == expected
		}
	}
	return allowAbsent
}

// Native server peers already own the landing's main transport; they must not
// keep using a client landing map as business authority after schema migration.
// Capture only an existing grant with its exact enrolled mTLS/source/transport
// bindings. No listener, grant, certificate or node plan is created here.
func migrateNativeServerLandings(nodes map[string]Node, original glivela.ImportMaterial, next *glivela.ImportMaterial) error {
	refused := errors.New("control: native server landing ownership migration requires exact enrolled binding")
	if err := validateEnrollmentRoles(nodes); err != nil {
		return refused
	}
	next.ManagedRouteLandings = maps.Clone(original.ManagedRouteLandings)
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	for _, a := range original.Plan.Accounts {
		for _, g := range a.Grants {
			if original.DeletedRoutes[g.ID] || original.ManagedRouteLandings[g.ID] != "" {
				continue
			}
			if _, imported := original.References.Nodes[g.EgressID]; imported {
				continue
			}
			owned := false
			for _, r := range next.ServerTransports {
				owned = owned || r.AccountID == a.Account.ID && r.EntryID == g.EntryID && r.EgressID == g.EgressID && r.Peer.ClientChainID == g.ClientChainID
			}
			if owned {
				continue
			}
			shared, known := original.ClientLandings[g.EgressID]
			if !known || shared.AccountID != a.Account.ID || g.ClientChainID != "" || g.IPv4EgressID != "" || !slices.ContainsFunc(original.ClientChains, func(c glivela.ClientChain) bool {
				return c.AccountID == a.Account.ID && c.EntryID == g.EntryID && c.EgressID == g.EgressID
			}) {
				return refused
			}
			entry, target := byID[g.EntryID], byID[g.EgressID]
			if entry.Desired.Entry == nil || entry.Desired.EntryNetwork == nil || entry.Desired.EntryNetwork.Source == nil || target.Desired.Landing == nil || !glivela.ValidIdentity(target.CertificateID) {
				return refused
			}
			member, enrolled := target.RouteEntries[entry.ID]
			source := entry.Desired.EntryNetwork.Source
			if !enrolled || member.CertificateID != entry.CertificateID || member.Address != source.Address {
				return refused
			}
			matched := false
			for _, peer := range entry.Desired.Entry.Peers {
				if peer.EgressID != target.ID || peer.ClientChainID != "" || peer.Transport.ClientListenerID != "" || peer.Address != target.Desired.Landing.Address || !reflect.DeepEqual(peer.Transport, target.Desired.Landing.Transport) || peer.Port != target.Desired.Landing.Transport.ListenerPort() {
					continue
				}
				if !slices.ContainsFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool {
					return p.PeerKey() == peer.PeerKey() && p.Identity.Address == target.Desired.Landing.Address
				}) {
					continue
				}
				matched = slices.ContainsFunc(target.Desired.Landing.Sources, func(p landing.Source) bool {
					return p.Address == source.Address && (peer.Transport.PublicAddress == "" || p.TCPOnly && glivela.PublicTransportIPv4(p.PublicAddress))
				})
			}
			if !matched {
				return refused
			}
			if next.ManagedRouteLandings == nil {
				next.ManagedRouteLandings = map[string]string{}
			}
			next.ManagedRouteLandings[g.ID] = target.CertificateID
		}
	}
	return nil
}

// One-way migration helpers retained solely to lift legacy Schema 0 ledgers into
// ServerTransportVersion 1 without consulting retired client-chain runtime code.
func chainLanding(nodes map[string]Node, c glivela.ClientChain) (Node, string, error) {
	if c.Transport == "ipv6-ss2022" {
		if c.Validate() != nil {
			return Node{}, "", errors.New("control: invalid IPv6 client chain")
		}
		entry, entryExists := nodes[c.EntryCertificateID]
		target, targetExists := nodes[c.LandingCertificateID]
		entryFamily := entryExists && entry.Desired.Entry != nil && (c.Relay != nil && c.Relay.Transport == glivela.IPv4RelaySS2022 && entry.Desired.Entry.NativeEgress != glivela.EgressIPv6Only || (c.Relay == nil || c.Relay.Transport != glivela.IPv4RelaySS2022) && entry.Desired.Entry.NativeEgress != glivela.EgressIPv4Only)
		if entryExists && targetExists && entry.CertificateID == c.EntryCertificateID && target.CertificateID == c.LandingCertificateID && entry.ID == c.EntryID && entryFamily && target.ID == c.EgressID && target.Desired.Landing != nil && (target.Desired.Landing.IPv6OnlyAddress == "" || target.Desired.Landing.IPv6OnlyAddress == c.ServerIPv6) {
			if c.Relay != nil {
				if _, err := chainRelay(nodes, c); err != nil {
					return Node{}, "", err
				}
			}
			return target, c.SourceIPv6, nil
		}
		return Node{}, "", errors.New("control: client chain requires enrolled entry and landing identities")
	}
	if c.Transport != "" && c.Transport != glivela.IPv4ClientSS2022 {
		return Node{}, "", errors.New("control: unsupported client chain transport")
	}
	for _, n := range nodes {
		if n.ID != c.EgressID || n.Desired.Landing == nil {
			continue
		}
		p := n.Desired.Landing
		member, ok := n.RouteEntries[c.EntryID]
		entry, known := nodes[member.CertificateID]
		if !ok || !known || entry.ID != c.EntryID || entry.Desired.Entry == nil || entry.Desired.Entry.NativeEgress == glivela.EgressIPv6Only || p.Transport.PublicAddress == "" {
			break
		}
		if c.PrivateLink != nil {
			if c.PrivateLink.Validate() != nil {
				break
			}
			return n, c.PrivateLink.Source, nil
		}
		for _, source := range p.Sources {
			if source.Address == member.Address && glivela.PublicTransportIPv4(source.PublicAddress) {
				return n, source.PublicAddress, nil
			}
		}
	}
	return Node{}, "", errors.New("control: client chain requires an enrolled public landing source")
}

func chainRelay(nodes map[string]Node, c glivela.ClientChain) (Node, error) {
	if c.Relay == nil {
		return Node{}, errors.New("control: client relay missing")
	}
	r := c.Relay
	node, ok := nodes[r.CertificateID]
	if !ok || node.CertificateID != r.CertificateID || node.ID != r.NodeID || node.Desired.Landing == nil || node.Desired.Landing.EgressIP != c.SourceIPv6 {
		return Node{}, errors.New("control: client relay requires an enrolled landing with matching IPv6 egress")
	}
	plan := node.Desired.Landing
	if r.Transport == glivela.IPv4RelaySS2022 && (plan.IPv6OnlyAddress != "" || plan.Transport.PublicAddress != r.ServerIPv4) || r.Transport == "" && plan.IPv6OnlyAddress != "" && plan.IPv6OnlyAddress != r.ServerIPv6 {
		return Node{}, errors.New("control: client relay listener address differs from enrollment")
	}
	return node, nil
}

func clientListener(c glivela.ClientChain, source string) landing.ClientListener {
	result := landing.ClientListener{EgressIP: c.EgressIP, Shared: c.Shared, ID: c.ID, Port: c.Port, Key: c.Key, Source: source, Transport: c.Transport, Address: c.ServerIPv6}
	if c.PrivateLink != nil {
		result.Address, result.Interface = c.PrivateLink.Address, c.PrivateLink.Interface
	}
	return result
}

func clientRelayListener(c glivela.ClientChain) landing.ClientListener {
	r := c.Relay
	if r.Transport == glivela.IPv4RelaySS2022 {
		return landing.ClientListener{ID: c.ID, Port: r.Port, Key: r.Key, Source: r.SourceIPv4, Transport: r.Transport}
	}
	return landing.ClientListener{ID: c.ID, Port: r.Port, Key: r.Key, Source: r.SourceIPv6, Transport: "ipv6-ss2022", Address: r.ServerIPv6}
}
