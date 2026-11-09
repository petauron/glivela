package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type ClientChainChange struct {
	ShareLanding     bool   `json:"shareLanding,omitempty"`
	RestoreLanding   bool   `json:"restoreLanding,omitempty"`
	Transport        string `json:"transport,omitempty"`
	SourceIPv6       string `json:"sourceIpv6,omitempty"`
	ServerIPv6       string `json:"serverIpv6,omitempty"`
	ID               string `json:"id"`
	AccountID        string `json:"accountId"`
	EntryID          string `json:"entryId"`
	EgressID         string `json:"egressId"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	Delete           bool   `json:"delete,omitempty"`
	ExpectedRevision uint64 `json:"expectedRevision,string"`
}

type ClientChainView struct {
	UnavailableReason string `json:"unavailableReason,omitempty"`
	Shared            bool   `json:"shared,omitempty"`
	Transport         string `json:"transport,omitempty"`
	SourceIPv6        string `json:"sourceIpv6,omitempty"`
	ServerIPv6        string `json:"serverIpv6,omitempty"`
	Port              int    `json:"port"`
	ID                string `json:"id"`
	AccountID         string `json:"accountId"`
	EntryID           string `json:"entryId"`
	EgressID          string `json:"egressId"`
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
}

// The existing public transport's enrolled source is an authorization boundary,
// not a key to disclose. Shared client credentials never reuse the server key.
func chainLanding(nodes map[string]Node, c glivela.ClientChain) (Node, string, error) {
	if c.Transport == "ipv6-ss2022" {
		if c.Validate() != nil {
			return Node{}, "", errors.New("control: invalid IPv6 client chain")
		}
		entry, entryExists := nodes[c.EntryCertificateID]
		target, targetExists := nodes[c.LandingCertificateID]
		// This association is created explicitly by the authenticated operator;
		// do not infer an IPv6 source from the old shared IPv4 transport grant.
		if entryExists && targetExists && entry.CertificateID == c.EntryCertificateID && target.CertificateID == c.LandingCertificateID && entry.ID == c.EntryID && entry.Desired.Entry != nil && entry.Desired.Entry.NativeEgress != glivela.EgressIPv4Only && target.ID == c.EgressID && target.Desired.Landing != nil && (target.Desired.Landing.IPv6OnlyAddress == "" || target.Desired.Landing.IPv6OnlyAddress == c.ServerIPv6) {
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
		for _, source := range p.Sources {
			if source.Address == member.Address && glivela.PublicTransportIPv4(source.PublicAddress) {
				return n, source.PublicAddress, nil
			}
		}
	}
	return Node{}, "", errors.New("control: client chain requires an enrolled public landing source")
}

func (s *Store) ChangeClientChain(ctx context.Context, c ClientChainChange) (AccountChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: client chain change refused")
	if err := ctx.Err(); err != nil {
		return AccountChangeResult{}, err
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || c.ExpectedRevision == 0 || c.ExpectedRevision == math.MaxUint64 {
		return AccountChangeResult{}, invalid
	}
	if c.ShareLanding || c.RestoreLanding {
		return s.changeSharedLandingLocked(c)
	}
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	ai := slices.IndexFunc(accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == c.AccountID })
	if ai < 0 {
		return AccountChangeResult{}, invalid
	}
	next.ClientChains = slices.Clone(next.ClientChains)
	ci := slices.IndexFunc(next.ClientChains, func(v glivela.ClientChain) bool { return v.ID == c.ID })
	deleted := next.DeletedClientChains[c.ID]
	if c.Delete && (c.Enabled || ci < 0) {
		return AccountChangeResult{}, invalid
	}
	same := false
	if ci >= 0 {
		old := next.ClientChains[ci]
		if _, shared := next.ClientLandings[old.EgressID]; shared && c.Transport != "" {
			effective, err := next.EffectiveClientChain(old)
			if err != nil || c.Transport != effective.Transport {
				return AccountChangeResult{}, invalid
			}
			c.Transport = old.Transport
		}
		upgrade := !c.Delete && old.Transport == "" && c.Transport == glivela.IPv4ClientSS2022
		if old.AccountID != c.AccountID || old.EntryID != c.EntryID || old.EgressID != c.EgressID || c.Transport != "" && c.Transport != old.Transport && !upgrade || c.SourceIPv6 != "" && c.SourceIPv6 != old.SourceIPv6 || c.ServerIPv6 != "" && c.ServerIPv6 != old.ServerIPv6 {
			return AccountChangeResult{}, invalid
		}
		if c.Delete && old.Name != c.Name {
			return AccountChangeResult{}, invalid
		}
		if c.Delete && !deleted && (old.Enabled || !clientChainDeletionReady(s.nodes, old, time.Now())) {
			return AccountChangeResult{}, errors.New("control: client chain must be disabled and applied before deletion")
		}
		same = old.Name == c.Name && old.Enabled == c.Enabled && deleted == c.Delete && (c.Transport == "" || c.Transport == old.Transport)
	}
	if deleted && !same {
		return AccountChangeResult{}, invalid
	}
	if accounts[ai].Account.DesiredRevision != c.ExpectedRevision && !(same && accounts[ai].Account.DesiredRevision == c.ExpectedRevision+1) {
		return AccountChangeResult{}, invalid
	}
	if !same {
		var chain glivela.ClientChain
		if ci >= 0 {
			chain = next.ClientChains[ci]
		} else {
			if !c.Enabled || len(next.ClientChains) >= 1000 {
				return AccountChangeResult{}, invalid
			}
			port := 24000
			for ; port <= 24999; port++ {
				if !slices.ContainsFunc(next.ClientChains, func(v glivela.ClientChain) bool {
					return !next.DeletedClientChains[v.ID] && v.EgressID == c.EgressID && v.Port == port
				}) {
					break
				}
			}
			keyLength := 32
			if c.Transport == "ipv6-ss2022" {
				keyLength = 16
			}
			key := make([]byte, keyLength)
			if _, err := rand.Read(key); err != nil {
				return AccountChangeResult{}, err
			}
			chain = glivela.ClientChain{ID: c.ID, AccountID: c.AccountID, EntryID: c.EntryID, EgressID: c.EgressID, Port: port, Key: base64.StdEncoding.EncodeToString(key), Transport: c.Transport, SourceIPv6: c.SourceIPv6, ServerIPv6: c.ServerIPv6}
			if c.Transport == "ipv6-ss2022" {
				for cert, node := range s.nodes {
					if node.ID == c.EntryID && node.Desired.Entry != nil && cert == node.CertificateID {
						chain.EntryCertificateID = cert
					}
					if node.ID == c.EgressID && node.Desired.Landing != nil && cert == node.CertificateID {
						chain.LandingCertificateID = cert
					}
				}
			}
		}
		if c.Transport != "" {
			chain.Transport = c.Transport
		}
		chain.Name, chain.Enabled = c.Name, c.Enabled
		if chain.Validate() != nil {
			return AccountChangeResult{}, invalid
		}
		if chain.Enabled {
			entryHost, landingHost := "", ""
			for _, node := range s.nodes {
				if node.ID == chain.EntryID {
					entryHost = runtimeHostID(next, node)
				}
				if node.ID == chain.EgressID {
					landingHost = runtimeHostID(next, node)
				}
			}
			if entryHost != "" && entryHost == landingHost {
				return AccountChangeResult{}, errors.New("control: client chain cannot loop through two roles on the same host")
			}
			if clientChainUnavailableReason(s.nodes, chain) != "" {
				return AccountChangeResult{}, errors.New("control: landing only accepts explicitly authorized IPv6 client chains")
			}
			if _, _, err := chainLanding(s.nodes, chain); err != nil {
				return AccountChangeResult{}, err
			}
			if !slices.ContainsFunc(next.Endpoints, func(e glivela.ImportEndpoint) bool {
				return e.Reality.EntryID == chain.EntryID && e.VLESSEnabled && !e.Retired
			}) {
				return AccountChangeResult{}, invalid
			}
		}
		if ci >= 0 {
			next.ClientChains[ci] = chain
		} else {
			next.ClientChains = append(next.ClientChains, chain)
		}
		if c.Delete {
			next.DeletedClientChains = maps.Clone(next.DeletedClientChains)
			if next.DeletedClientChains == nil {
				next.DeletedClientChains = make(map[string]bool)
			}
			next.DeletedClientChains[c.ID] = true
		}
		if c.Delete && !slices.ContainsFunc(next.ClientChains, func(v glivela.ClientChain) bool { return v.EgressID == c.EgressID && !next.DeletedClientChains[v.ID] }) {
			next.ClientLandings = maps.Clone(next.ClientLandings)
			delete(next.ClientLandings, c.EgressID)
		}
		accounts[ai].Account.DesiredRevision++
		var err error
		next.Plan, err = glivela.PlanImport(accounts)
		if err != nil {
			return AccountChangeResult{}, err
		}
	}
	if err := next.Validate(); err != nil {
		return AccountChangeResult{}, invalid
	}
	projected, changed, err := projectBusinessEntries(s.nodes, next, time.Now())
	if err != nil {
		return AccountChangeResult{}, err
	}
	if c.Delete && changed {
		return AccountChangeResult{}, errors.New("control: deletion would change a node runtime")
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return AccountChangeResult{}, err
	}
	if changed {
		if err := s.commit(projected); err != nil {
			return AccountChangeResult{}, err
		}
	}
	return s.accountChangeResult(c.AccountID, time.Now()), nil
}

// A deleted chain keeps its identity and history, but its landing listener
// must already be absent from the freshly confirmed desired configuration.
func clientChainDeletionReady(nodes map[string]Node, chain glivela.ClientChain, now time.Time) bool {
	for _, node := range nodes {
		if node.ID != chain.EgressID || node.Desired.Landing == nil || !runtimeFresh(node, now) {
			continue
		}
		return !slices.ContainsFunc(node.Desired.Landing.ClientListeners, func(listener landing.ClientListener) bool {
			return listener.ID == chain.ID
		})
	}
	return false
}

func projectClientLandings(nodes map[string]Node, m glivela.ImportMaterial, now time.Time) (bool, error) {
	credentials, _, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return false, err
	}
	wanted := map[string][]landing.ClientListener{}
	for _, original := range m.ClientChains {
		c, err := m.EffectiveClientChain(original)
		if err != nil {
			return false, err
		}
		if !c.Enabled {
			continue
		}
		active := false
		for _, cred := range credentials {
			if cred.Credential.AccountID == c.AccountID && cred.Credential.EntryID == c.EntryID && cred.Credential.Kind == glivela.NativeCredential && cred.Credential.Enabled {
				active = true
			}
		}
		if !active {
			continue
		}
		n, source, err := chainLanding(nodes, c)
		if err != nil {
			// Revoked enrollment must withdraw this listener, not block other
			// accounts' revocation while retaining an old active credential.
			continue
		}
		wanted[n.ID] = append(wanted[n.ID], clientListener(c, source))
	}
	changed := false
	for cert, n := range nodes {
		if n.Desired.Landing == nil {
			continue
		}
		plan := *n.Desired.Landing
		listeners := wanted[n.ID]
		if reflect.DeepEqual(plan.ClientListeners, listeners) {
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return false, errors.New("control: landing revision exhausted")
		}
		plan.ClientListeners = listeners
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

func clientListener(c glivela.ClientChain, source string) landing.ClientListener {
	return landing.ClientListener{Shared: c.Shared, ID: c.ID, Port: c.Port, Key: c.Key, Source: source, Transport: c.Transport, Address: c.ServerIPv6}
}

// A retained IPv4 record is not authority to bind a new address or fall back.
func clientChainUnavailableReason(nodes map[string]Node, c glivela.ClientChain) string {
	for _, n := range nodes {
		if n.ID == c.EgressID && n.Desired.Landing != nil && n.Desired.Landing.IPv6OnlyAddress != "" && (c.Transport != "ipv6-ss2022" || c.ServerIPv6 != n.Desired.Landing.IPv6OnlyAddress) {
			return "landing_ipv6_only"
		}
	}
	return ""
}
