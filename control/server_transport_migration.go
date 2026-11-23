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
	if original.ServerTransportVersion == 1 {
		return original, false, nil
	}
	if original.ServerTransportVersion != 0 {
		return original, false, errors.New("control: unknown server transport schema")
	}
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
