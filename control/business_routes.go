package control

import (
	"context"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

type RouteChange struct {
	UDP              bool   `json:"udp,omitempty"`
	ClientChainID    string `json:"clientChainId,omitempty"`
	RelayPoolID      string `json:"relayPoolId,omitempty"`
	LandingAddress   string `json:"landingAddress,omitempty"`
	ExpectedExit     string `json:"expectedExit,omitempty"`
	EgressIP         string `json:"egressIp,omitempty"`
	IngressFamily    string `json:"ingressFamily,omitempty"`
	Name             string `json:"name,omitempty"`
	ID               string `json:"id"`
	AccountID        string `json:"accountId"`
	EntryID          string `json:"entryId"`
	EgressID         string `json:"egressId"`
	IPv4EgressID     string `json:"ipv4EgressId,omitempty"`
	HideNative       bool   `json:"hideNative"`
	Enabled          bool   `json:"enabled"`
	Delete           bool   `json:"delete,omitempty"`
	ExpectedRevision uint64 `json:"expectedRevision,string"`
}

// ChangeRoute grants only an already enrolled, explicitly authorized peer.
// It never adds a firewall source, guesses a peer identity or creates a host
// resource. Revocation retains credentials, usage and history but gates access.
func (s *Store) ChangeRoute(ctx context.Context, change RouteChange) (AccountChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: route change refused")
	if err := ctx.Err(); err != nil {
		return AccountChangeResult{}, err
	}
	if !glivela.ValidIdentifier(change.ID) || !glivela.ValidIdentifier(change.AccountID) || !glivela.ValidIdentifier(change.EntryID) || !glivela.ValidIdentifier(change.EgressID) || change.ExpectedRevision == 0 || change.ExpectedRevision == math.MaxUint64 || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return AccountChangeResult{}, invalid
	}
	if s.entryRetiredLocked(change.EntryID) || change.ClientChainID != "" {
		return AccountChangeResult{}, invalid
	}
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	ai := slices.IndexFunc(accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == change.AccountID })
	if ai < 0 {
		return AccountChangeResult{}, invalid
	}
	var pooledTarget Node
	if change.RelayPoolID != "" {
		if change.IPv4EgressID != "" || change.EntryID == change.EgressID || next.ServerTransportVersion != glivela.CurrentServerTransportVersion {
			return AccountChangeResult{}, invalid
		}
		if _, hasPool := next.RelayPools[change.RelayPoolID]; !hasPool {
			return AccountChangeResult{}, invalid
		}
		foundTarget := false
		for _, target := range s.nodes {
			if target.ID == change.EgressID && target.Desired.Landing != nil && !entryRetired(next, target.ID) {
				pooledTarget, foundTarget = target, true
				break
			}
		}
		if !foundTarget {
			return AccountChangeResult{}, invalid
		}
		if !change.Delete && change.Enabled {
			entryCapable := false
			for _, entry := range s.nodes {
				if entry.ID == change.EntryID && entry.Desired.Entry != nil {
					entryCapable = entryKnownRelayPoolCapable(entry)
					break
				}
			}
			if !entryCapable {
				return AccountChangeResult{}, errors.New("control: entry runtime does not support relay pools")
			}
		}
	}
	if change.Enabled && change.RelayPoolID == "" {
		for _, entry := range s.nodes {
			if entry.ID != change.EntryID || entry.Desired.Entry == nil {
				continue
			}
			for _, peer := range entry.Desired.Entry.Peers {
				if peer.EgressID != change.EgressID || peer.ClientChainID != "" || peer.Transport.ClientListenerID == "" {
					continue
				}
				authorized := false
				for _, target := range s.nodes {
					if target.ID == change.EgressID {
						chain, ok := s.configuredServerTransport(entry, target, peer)
						authorized = ok && chain.AccountID == change.AccountID
					}
				}
				if !authorized {
					return AccountChangeResult{}, invalid
				}
			}
		}
	}
	account := &accounts[ai]
	gi := slices.IndexFunc(account.Grants, func(g glivela.RouteGrant) bool { return g.ID == change.ID })
	deleted := next.DeletedRoutes[change.ID]
	same := gi >= 0 && account.Grants[gi].UDP == change.UDP && account.Grants[gi].EntryID == change.EntryID && account.Grants[gi].EgressID == change.EgressID && account.Grants[gi].IPv4EgressID == change.IPv4EgressID && account.Grants[gi].ClientChainID == "" && account.Grants[gi].RelayPoolID == change.RelayPoolID && account.Grants[gi].HideNative == change.HideNative && account.Grants[gi].Enabled == change.Enabled && deleted == change.Delete
	if change.Delete && (change.Enabled || gi < 0 || account.Grants[gi].HideNative != change.HideNative) || deleted && !same {
		return AccountChangeResult{}, invalid
	}
	if change.Delete && !deleted && (account.Grants[gi].Enabled || !routeDeletionReady(s.nodes, account.Grants[gi], time.Now())) {
		return AccountChangeResult{}, errors.New("control: route must be disabled and applied before deletion")
	}
	if account.Account.DesiredRevision != change.ExpectedRevision && !(same && account.Account.DesiredRevision == change.ExpectedRevision+1) {
		return AccountChangeResult{}, invalid
	}
	now := time.Now().UTC()
	if _, _, err := s.projectBusinessLocked(s.nodes, next, now); err != nil {
		return AccountChangeResult{}, err
	}
	if !same {
		if account.Account.DesiredRevision == math.MaxUint64 {
			return AccountChangeResult{}, invalid
		}
		account.Grants = slices.Clone(account.Grants)
		if gi >= 0 {
			grant := &account.Grants[gi]
			// Changing a route's exits/identity is a new grant, not credential reuse.
			if grant.EntryID != change.EntryID || grant.EgressID != change.EgressID || grant.IPv4EgressID != change.IPv4EgressID || grant.ClientChainID != "" || grant.RelayPoolID != change.RelayPoolID || grant.DesiredRev == math.MaxUint64 {
				return AccountChangeResult{}, invalid
			}
			if !change.Delete {
				if change.RelayPoolID == "" && change.Enabled && (!grant.Enabled || !grant.UDP && change.UDP) && next.ManagedRouteLandings[change.ID] != "" {
					cert, err := s.managedRouteReactivationCertificate(change)
					if err != nil || cert != next.ManagedRouteLandings[change.ID] {
						return AccountChangeResult{}, invalid
					}
				}
				grant.Enabled, grant.HideNative, grant.UDP = change.Enabled, change.HideNative, change.UDP
				grant.DesiredRev++
				grant.AppliedRev, grant.RuntimeGood = 0, false
			}
		} else {
			if !change.Enabled {
				return AccountChangeResult{}, invalid
			}
			base := slices.IndexFunc(account.Credentials, func(c glivela.Credential) bool {
				return c.Kind == glivela.NativeCredential && c.EntryID == change.EntryID
			})
			ei := slices.IndexFunc(next.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == change.EntryID && !e.Retired })
			if base < 0 || ei < 0 {
				return AccountChangeResult{}, invalid
			}
			identity, err := uuid.NewRandom()
			if err != nil {
				return AccountChangeResult{}, err
			}
			cid, err := uuid.NewRandom()
			if err != nil {
				return AccountChangeResult{}, err
			}
			credential := glivela.Credential{ID: cid.String(), AccountID: change.AccountID, Kind: glivela.RouteCredential, User: glivela.RouteUser(change.ID), Identity: glivela.Identity(identity.String()), EntryID: change.EntryID, EgressID: change.EgressID, Enabled: true}
			grant := glivela.RouteGrant{UDP: change.UDP, RelayPoolID: change.RelayPoolID, ID: change.ID, AccountID: change.AccountID, EntryID: change.EntryID, EgressID: change.EgressID, IPv4EgressID: change.IPv4EgressID, InboundTag: next.Endpoints[ei].Reality.InboundTag, Base: account.Credentials[base], Route: credential, Mode: glivela.FixedMode, Enabled: true, HideNative: change.HideNative, DesiredRev: 1}
			if grant.Validate() != nil {
				return AccountChangeResult{}, invalid
			}
			if change.RelayPoolID != "" {
				landingAddr := change.LandingAddress
				if landingAddr == "" {
					if pooledTarget.Desired.Landing.IPv6OnlyAddress != "" {
						landingAddr = pooledTarget.Desired.Landing.IPv6OnlyAddress
					} else {
						landingAddr = pooledTarget.Desired.Landing.Transport.PublicAddress
					}
				}
				expectedExit := change.ExpectedExit
				if expectedExit == "" {
					expectedExit = pooledTarget.Desired.Landing.EgressIP
				}
				pr := glivela.PooledRoute{
					GrantID:              change.ID,
					AccountID:            change.AccountID,
					EntryID:              change.EntryID,
					EgressID:             change.EgressID,
					RelayPoolID:          change.RelayPoolID,
					LandingCertificateID: pooledTarget.CertificateID,
					LandingAddress:       landingAddr,
					ExpectedExit:         expectedExit,
					EgressIP:             change.EgressIP,
					IngressFamily:        change.IngressFamily,
					Name:                 change.Name,
				}
				if pr.Validate() != nil {
					return AccountChangeResult{}, invalid
				}
				next.PooledRoutes = maps.Clone(next.PooledRoutes)
				if next.PooledRoutes == nil {
					next.PooledRoutes = map[string]glivela.PooledRoute{}
				}
				next.PooledRoutes[change.ID] = pr
			} else if _, imported := next.References.Nodes[change.EgressID]; !imported {
				cert, err := s.managedRouteReactivationCertificate(change)
				if err != nil {
					return AccountChangeResult{}, err
				}
				next.ManagedRouteLandings = maps.Clone(next.ManagedRouteLandings)
				if next.ManagedRouteLandings == nil {
					next.ManagedRouteLandings = map[string]string{}
				}
				next.ManagedRouteLandings[change.ID] = cert
			}

			account.Grants = append(account.Grants, grant)
			account.Credentials = append(slices.Clone(account.Credentials), credential)
			account.Usage = append(slices.Clone(account.Usage), glivela.UsageMember{CredentialID: credential.ID, Active: true})
			next.ProtocolSecrets = maps.Clone(next.ProtocolSecrets)
			next.ProtocolSecrets[credential.ID] = identity.String()
			next.TrafficCounters = maps.Clone(next.TrafficCounters)
			next.TrafficCounters[credential.ID] = glivela.ImportTrafficCounters{}
		}
		if change.Delete {
			next.DeletedRoutes = maps.Clone(next.DeletedRoutes)
			if next.DeletedRoutes == nil {
				next.DeletedRoutes = make(map[string]bool)
			}
			next.DeletedRoutes[change.ID] = true
			if _, hasPR := next.PooledRoutes[change.ID]; hasPR {
				next.PooledRoutes = maps.Clone(next.PooledRoutes)
				delete(next.PooledRoutes, change.ID)
				if len(next.PooledRoutes) == 0 {
					next.PooledRoutes = nil
				}
			}
		}
		account.Account.DesiredRevision++
		var err error
		next.Plan, err = glivela.PlanImport(accounts)
		if err != nil {
			return AccountChangeResult{}, err
		}
		if err := ensurePooledRouteCredentials(s.nodes, &next); err != nil {
			return AccountChangeResult{}, err
		}
		if change.Delete {
			pruneUnreferencedTwoHopEIHBindings(&next, s.nodes, s.socketCutovers, now)
		}
		gcUnreferencedRelayPoolCredentials(&next, s.nodes, s.socketCutovers)
	}
	var projected map[string]Node
	var err error
	if change.Delete {
		// A ledger deletion must preserve the enrolled credential set, including
		// credentials already withdrawn from native runtime during handover.
		projected, _, err = s.projectBusinessLocked(s.nodes, next, now)
	} else {
		projected, err = projectManagedRoutes(s.nodes, next, change.EntryID, now, func(id string) bool { return s.suspended(id, now) }, s.socketCutovers)
	}
	if err != nil {
		return AccountChangeResult{}, err
	}
	if !change.Delete {
		if _, err := projectServerLandings(projected, next, now, s.socketCutovers); err != nil {
			return AccountChangeResult{}, err
		}
		if _, err := projectRelayPools(projected, next, now, func(id string) bool { return s.suspended(id, now) }, s.socketCutovers); err != nil {
			return AccountChangeResult{}, err
		}
	}
	if change.Delete && !reflect.DeepEqual(projected, s.nodes) {
		return AccountChangeResult{}, errors.New("control: deletion would change an entry runtime")
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return AccountChangeResult{}, err
	}
	if !change.Delete {
		if err := s.commit(projected); err != nil {
			return AccountChangeResult{}, err
		}
	}
	return s.accountChangeResult(change.AccountID, time.Now()), nil
}

// Deletion only hides a disabled record after its entry confirms the disabled
// configuration. The historical credential and traffic ledger remain intact.
func routeDeletionReady(nodes map[string]Node, grant glivela.RouteGrant, now time.Time) bool {
	for _, node := range nodes {
		if node.ID != grant.EntryID || node.Desired.Entry == nil || !runtimeFresh(node, now) {
			continue
		}
		for _, current := range node.Desired.Entry.Grants {
			if current.ID == grant.ID {
				return current.EntryID == grant.EntryID && current.EgressID == grant.EgressID && current.IPv4EgressID == grant.IPv4EgressID && current.ClientChainID == grant.ClientChainID && current.RelayPoolID == grant.RelayPoolID && !current.Enabled && !current.Route.Enabled
			}
		}
		// A fresh applied plan without this grant already proves withdrawal.
		// Deletion only hides its disabled ledger record; projection below must
		// still confirm that no runtime policy would change.
		return true
	}
	return false
}

// Rebuild only the selected entry's business users from the authoritative
// ledger. Transport/peer enrollment remains unchanged and must match exactly.
func projectManagedRoutes(nodes map[string]Node, material glivela.ImportMaterial, entryID string, now time.Time, isSuspended func(string) bool, cutovers map[string]SocketCutover) (map[string]Node, error) {
	credentials, grants, err := effectiveBusinessCredentials(material, now)
	if err != nil {
		return nil, err
	}
	next := maps.Clone(nodes)
	found := false
	for certificate, node := range nodes {
		if node.ID != entryID || node.Desired.Entry == nil {
			continue
		}
		found = true
		desired := node.Desired.clone()
		plan := desired.Entry
		plan.Credentials, plan.Grants = nil, nil
		hasPooled := false
		for _, account := range material.Plan.Accounts {
			for _, credential := range account.Credentials {
				if credential.EntryID == entryID {
					plan.Credentials = append(plan.Credentials, credentials[credential.ID])
				}
			}
			for _, grant := range account.Grants {
				// Deletion itself does not change a running entry. Preserve a
				// retained disabled grant until explicit resource retirement,
				// but never reintroduce it after native handover omitted it.
				retained := slices.ContainsFunc(node.Desired.Entry.Grants, func(current glivela.RouteGrant) bool { return current.ID == grant.ID })
				if grant.EntryID == entryID && (!material.DeletedRoutes[grant.ID] || retained) {
					g := grants[grant.ID]
					plan.Grants = append(plan.Grants, g)
					if g.RelayPoolID != "" {
						hasPooled = true
					}
				}
			}
		}
		used := map[string]bool{}
		for _, grant := range plan.Grants {
			if grant.RelayPoolID != "" {
				continue
			}
			used[grant.PeerKey()] = true
			if grant.IPv4EgressID != "" {
				used[grant.IPv4EgressID] = true
			}
		}
		// Disabled grants retain their transport until explicit resource retirement.
		for id := range used {
			if !slices.ContainsFunc(plan.Peers, func(p glivela.RoutePeer) bool { return p.PeerKey() == id }) {
				return nil, errors.New("control: enroll authorized entry transport before granting route")
			}
		}
		if reflect.DeepEqual(plan, node.Desired.Entry) {
			continue
		}
		if hasPooled {
			node.Desired.Entry = plan
			node.Desired.EntryNetwork = desired.EntryNetwork
			next[certificate] = node
			if _, err := projectRelayPools(next, material, now, isSuspended, cutovers); err != nil {
				return nil, err
			}
			// If projectRelayPools did not bump revision because pool structure
			// stayed unchanged while grant flags changed, finalize the revision now.
			if next[certificate].Desired.Validate() != nil || next[certificate].Desired.Revision == nodes[certificate].Desired.Revision {
				updated := next[certificate]
				if updated.Desired.Entry.Revision == math.MaxUint64 {
					return nil, errors.New("control: entry revision exhausted")
				}
				updated.Desired.Entry.Revision++
				rebuilt, err := newEntryDesiredVersion(*updated.Desired.Entry, *updated.Desired.EntryNetwork, glivela.XrayRenderVersion)
				if err != nil {
					return nil, err
				}
				updated.Desired, updated.Receipt, updated.ReportedAt, updated.EntryHealthBarrierAt = rebuilt, nil, time.Time{}, time.Time{}
				next[certificate] = updated
				invalidateEntryChecks(next, updated.ID)
			}
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return nil, errors.New("control: entry revision exhausted")
		}
		plan.Revision++
		if slices.ContainsFunc(plan.Grants, func(g glivela.RouteGrant) bool { return g.UDP }) {
			desired.EntryRenderVersion = glivela.XrayRenderVersion
		}
		desired, err = newEntryDesiredVersion(*plan, *desired.EntryNetwork, desired.EntryRenderVersion)
		if err != nil {
			return nil, err
		}
		node.Desired, node.Receipt, node.ReportedAt, node.EntryHealthBarrierAt = desired, nil, time.Time{}, time.Time{}
		next[certificate] = node
		invalidateEntryChecks(next, node.ID)
	}
	if !found {
		return nil, errors.New("control: entry not enrolled")
	}
	return next, nil
}

// The caller holds the store lock. Reuse exactly the public peer mTLS/source
// authority check; a runtime observation alone never grants an account access.
func (s *Store) managedRouteLandingCertificate(change RouteChange) (string, error) {
	refused := errors.New("control: managed server landing enrollment unavailable")
	if change.IPv4EgressID != "" {
		return "", refused
	}
	for cert, entry := range s.nodes {
		if entry.ID != change.EntryID {
			continue
		}
		peerKey := change.EgressID
		if change.ClientChainID != "" {
			peerKey = change.ClientChainID
		}
		proof, err := s.publicPeerAcceptanceLocked(cert, landingAcceptanceRequest{SnapshotID: entry.ID, PeerID: peerKey, Revision: entry.Desired.Revision, ConfigSHA256: entry.Desired.ConfigSHA256})
		if err != nil {
			return "", refused
		}
		for targetCert, target := range s.nodes {
			if target.ID == proof.LandingID {
				for _, peer := range entry.Desired.Entry.Peers {
					if peer.EgressID == target.ID && peer.ClientChainID == change.ClientChainID && peer.Transport.ClientListenerID != "" {
						c, ok := s.boundServerTransport(entry, target, peer)
						if !ok || c.AccountID != change.AccountID {
							return "", refused
						}
					}
				}
				return targetCert, nil
			}
		}
	}
	return "", refused
}

// Reactivating an existing grant may restore a withdrawn owned listener. Check
// current mTLS identities first; actual startup/publication still uses the full
// applied-listener proof and cannot become ready through this metadata check.
func (s *Store) managedRouteReactivationCertificate(change RouteChange) (string, error) {
	refused := errors.New("control: managed server reactivation identity unavailable")
	if change.IPv4EgressID != "" {
		return "", refused
	}
	for _, entry := range s.nodes {
		if entry.ID != change.EntryID || entry.Desired.Entry == nil || entry.Desired.EntryNetwork == nil {
			continue
		}
		for _, peer := range entry.Desired.Entry.Peers {
			if peer.EgressID != change.EgressID || peer.ClientChainID != change.ClientChainID {
				continue
			}
			if peer.Transport.ClientListenerID == "" {
				if strings.Contains(peer.Transport.Key, ":") {
					for cert, target := range s.nodes {
						if target.ID != change.EgressID || target.Desired.Landing == nil {
							continue
						}
						authorized, ok := target.RouteEntries[entry.ID]
						if !ok || entry.Desired.EntryNetwork.Source == nil || authorized.CertificateID != entry.CertificateID || authorized.Address != entry.Desired.EntryNetwork.Source.Address || authorized.EIHAddress != peer.Transport.PublicAddress {
							return "", refused
						}
						for _, network := range entry.Desired.EntryNetwork.Peers {
							if network.PeerKey() != peer.PeerKey() {
								continue
							}
							now := time.Now()
							if !s.availableRuntime(target, now) || target.Receipt.ManagementIdentity == nil || *target.Receipt.ManagementIdentity != network.Identity || network.Identity.Address != target.Desired.Landing.Address {
								return "", refused
							}
							return cert, nil
						}
					}
					return "", refused
				}
				return s.managedRouteLandingCertificate(change)
			}
			for cert, target := range s.nodes {
				if target.ID != change.EgressID {
					continue
				}
				r, ok := s.configuredServerTransport(entry, target, peer)
				if !ok || r.AccountID != change.AccountID {
					return "", refused
				}
				for _, network := range entry.Desired.EntryNetwork.Peers {
					if network.PeerKey() != peer.PeerKey() {
						continue
					}
					now := time.Now()
					if !s.availableRuntime(target, now) || target.Receipt.ManagementIdentity == nil || *target.Receipt.ManagementIdentity != network.Identity || network.Identity.Address != target.Desired.Landing.Address {
						return "", refused
					}
					return cert, nil
				}
			}
		}
	}
	return "", refused
}
