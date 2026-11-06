package control

import (
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
)

func publicSpeedAddresses(address, source string) bool {
	return address != source && (glivela.PublicTransportIPv4(address) && glivela.PublicTransportIPv4(source) || glivela.PublicTransportIPv6(address) && glivela.PublicTransportIPv6(source))
}

// The pair comes from owned business policy and exact enrolled identities. It
// adds no Xray grant, peer, listener, credential or subscription entry.
func chainSpeedPeer(nodes map[string]Node, m glivela.ImportMaterial, c glivela.ClientChain, credentials map[string]glivela.CredentialMaterial) (EntrySpeedPeer, Node, Node, bool) {
	var err error
	c, err = m.EffectiveClientChain(c)
	if err != nil {
		return EntrySpeedPeer{}, Node{}, Node{}, false
	}
	if !c.Enabled || m.DeletedClientChains[c.ID] || entryRetired(m, c.EntryID) {
		return EntrySpeedPeer{}, Node{}, Node{}, false
	}
	active := false
	for _, a := range m.Plan.Accounts {
		if a.Account.ID == c.AccountID && a.Account.Plan.Enabled {
			active = true
		}
	}
	if !active {
		return EntrySpeedPeer{}, Node{}, Node{}, false
	}
	active = false
	for _, cred := range credentials {
		if cred.Credential.Enabled && cred.Credential.Kind == glivela.NativeCredential && cred.Credential.AccountID == c.AccountID && cred.Credential.EntryID == c.EntryID {
			active = true
		}
	}
	if !active {
		return EntrySpeedPeer{}, Node{}, Node{}, false
	}
	landing, source, err := chainLanding(nodes, c)
	if err != nil || !slices.Contains(landing.Desired.Landing.ClientListeners, clientListener(c, source)) {
		return EntrySpeedPeer{}, Node{}, Node{}, false
	}
	cert := c.EntryCertificateID
	address := c.ServerIPv6
	if c.Transport == "" || c.Transport == glivela.IPv4ClientSS2022 {
		cert = landing.RouteEntries[c.EntryID].CertificateID
		address = landing.Desired.Landing.Transport.PublicAddress
	}
	entry, ok := nodes[cert]
	if !ok || entry.ID != c.EntryID || entry.Desired.Entry == nil || !publicSpeedAddresses(address, source) {
		return EntrySpeedPeer{}, Node{}, Node{}, false
	}
	return EntrySpeedPeer{ChainID: c.ID, AccountID: c.AccountID, LandingID: c.EgressID, Address: address, Source: source}, entry, landing, true
}

func projectClientSpeedPeers(nodes map[string]Node, m glivela.ImportMaterial, credentials map[string]glivela.CredentialMaterial) (bool, error) {
	wanted := map[string][]EntrySpeedPeer{}
	for _, c := range m.ClientChains {
		peer, entry, _, ok := chainSpeedPeer(nodes, m, c, credentials)
		if ok {
			wanted[entry.CertificateID] = append(wanted[entry.CertificateID], peer)
		}
	}
	changed := false
	for cert, n := range nodes {
		if n.Desired.Entry == nil || n.Desired.EntryNetwork == nil {
			continue
		}
		peers := wanted[cert]
		slices.SortFunc(peers, func(a, b EntrySpeedPeer) int { return strings.Compare(a.ChainID, b.ChainID) })
		if reflect.DeepEqual(n.Desired.EntryNetwork.SpeedPeers, peers) {
			continue
		}
		d := n.Desired.clone()
		if d.Revision == math.MaxUint64 {
			return false, errors.New("control: entry revision exhausted")
		}
		d.Entry.Revision++
		d.EntryNetwork.SpeedPeers = peers
		d, err := newEntryDesiredVersion(*d.Entry, *d.EntryNetwork, d.EntryRenderVersion)
		if err != nil {
			return false, err
		}
		n.Desired, n.Receipt, n.ReportedAt, n.EntryHealthBarrierAt = d, nil, time.Time{}, time.Time{}
		nodes[cert] = n
		invalidateEntryChecks(nodes, n.ID)
		changed = true
	}
	return changed, nil
}

func (s *Store) chainSpeedPairLocked(entryID, landingID string, requireFresh bool) (latencyTarget, string, string, error) {
	fail := errors.New("pair_unavailable")
	m := s.business.material
	now := time.Now()
	credentials, _, err := effectiveBusinessCredentials(m, now)
	if err != nil || s.suspended(entryID, now) || s.suspended(landingID, now) {
		return latencyTarget{}, "", "", fail
	}
	chains := slices.Clone(m.ClientChains)
	slices.SortFunc(chains, func(a, b glivela.ClientChain) int { return strings.Compare(a.ID, b.ID) })
	for _, c := range chains {
		if c.EntryID != entryID || c.EgressID != landingID {
			continue
		}
		c, err = m.EffectiveClientChain(c)
		if err != nil {
			return latencyTarget{}, "", "", fail
		}
		peer, entry, landing, ok := chainSpeedPeer(s.nodes, m, c, credentials)
		if !ok || entry.Desired.EntryNetwork == nil || !slices.Contains(entry.Desired.EntryNetwork.SpeedPeers, peer) {
			continue
		}
		t := latencyTarget{Certificate: entry.CertificateID, EntryRevision: entry.Desired.Revision, LandingRevision: landing.Desired.Revision, EntryHash: entry.Desired.ConfigSHA256, LandingHash: landing.Desired.ConfigSHA256, Address: peer.Address, EntryID: entryID, LandingID: landingID, Port: c.Port}
		if c.Transport == "ipv6-ss2022" {
			t.Source = peer.Source
		}
		if requireFresh && !s.latencyOnlineLocked(t, now) {
			continue
		}
		if !requireFresh {
			projected, _, err := projectBusinessEntries(s.nodes, m, now)
			if err != nil || !reflect.DeepEqual(projected[entry.CertificateID].Desired, entry.Desired) || !reflect.DeepEqual(projected[landing.CertificateID].Desired, landing.Desired) {
				continue
			}
		}
		return t, landing.CertificateID, peer.Source, nil
	}
	return latencyTarget{}, "", "", fail
}
