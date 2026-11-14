package control

import (
	"encoding/json"
	"errors"
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
