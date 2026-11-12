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
	for _, original := range s.business.material.ClientChains {
		if original.ID != route.Transport.ClientListenerID {
			continue
		}
		c, err := s.business.material.EffectiveClientChain(original)
		if err != nil || c.Relay != nil || c.EntryID != entry.ID || c.EgressID != target.ID || c.Transport == "ipv6-ss2022" && (c.EntryCertificateID != entry.CertificateID || c.LandingCertificateID != target.CertificateID) || c.Transport != "ipv6-ss2022" && c.Transport != glivela.IPv4ClientSS2022 {
			return glivela.ClientChain{}, false
		}
		n, source, err := chainLanding(s.nodes, c)
		if err != nil || n.ID != target.ID {
			return glivela.ClientChain{}, false
		}
		listener := clientListener(c, source)
		expectedExit := c.EgressIP
		if expectedExit == "" {
			expectedExit = target.Desired.Landing.EgressIP
		}
		if entry.Desired.EntryNetwork == nil || !slices.ContainsFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool { return p.EgressID == target.ID && p.ExpectedExit == expectedExit }) {
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
	if err != nil || c.Relay != nil {
		return false
	}
	for _, n := range nodes {
		if n.ID != c.EntryID || n.Desired.Entry == nil || c.Transport == "ipv6-ss2022" && n.CertificateID != c.EntryCertificateID {
			continue
		}
		for _, peer := range n.Desired.Entry.Peers {
			if peer.EgressID != c.EgressID || peer.Transport.ClientListenerID != c.ID {
				continue
			}
			for _, g := range grants {
				if g.AccountID == c.AccountID && g.EntryID == c.EntryID && g.EgressID == c.EgressID && g.Enabled && g.Route.Enabled {
					return true
				}
			}
		}
	}
	return false
}
