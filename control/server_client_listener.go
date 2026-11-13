package control

import (
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// Bound listeners retain their original account, mTLS enrollment, exact source,
// cipher, destination and exit binding. No listener is created by this lookup.
func (s *Store) boundClientListener(entry Node, target Node, route glivela.RoutePeer) (glivela.ClientChain, bool) {
	if s.business == nil || target.Desired.Landing == nil {
		return glivela.ClientChain{}, false
	}
	return boundClientListenerIn(s.nodes, s.business.material, entry, target, route)
}

func boundClientListenerIn(nodes map[string]Node, material glivela.ImportMaterial, entry, target Node, route glivela.RoutePeer) (glivela.ClientChain, bool) {
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
		if c.Relay != nil {
			relay, err := chainRelay(nodes, c)
			if err != nil || !slices.ContainsFunc(relay.Desired.Landing.ClientListeners, func(l landing.ClientListener) bool { return reflect.DeepEqual(l, clientRelayListener(c)) }) {
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
		if route.Transport.PublicAddress != address || route.Transport.Key != c.Key || route.Port != c.Port || route.Transport.ListenerPort() != c.Port || !slices.ContainsFunc(target.Desired.Landing.ClientListeners, func(l landing.ClientListener) bool { return reflect.DeepEqual(l, listener) }) {
			return glivela.ClientChain{}, false
		}
		return c, true
	}
	return glivela.ClientChain{}, false
}

// A disabled client publication retains its socket only while the original
// account has an effective enabled server grant bound to that exact listener.
func clientListenerUsedByServer(nodes map[string]Node, m glivela.ImportMaterial, c glivela.ClientChain, now time.Time) bool {
	_, grants, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return false
	}
	for _, n := range nodes {
		if n.ID != c.EntryID || n.Desired.Entry == nil || c.Transport == "ipv6-ss2022" && n.CertificateID != c.EntryCertificateID {
			continue
		}
		for _, peer := range n.Desired.Entry.Peers {
			if peer.EgressID != c.EgressID || peer.Transport.ClientListenerID != c.ID || !reflect.DeepEqual(peer.Relay, c.Relay) || (c.Relay != nil && peer.ClientChainID != c.ID) {
				continue
			}
			for _, g := range grants {
				if g.AccountID == c.AccountID && g.EntryID == c.EntryID && g.EgressID == c.EgressID && g.ClientChainID == peer.ClientChainID && g.Enabled && g.Route.Enabled {
					return true
				}
			}
		}
	}
	return false
}
