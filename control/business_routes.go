package control

import (
	"context"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

type RouteChange struct {
	ID               string `json:"id"`
	AccountID        string `json:"accountId"`
	EntryID          string `json:"entryId"`
	EgressID         string `json:"egressId"`
	IPv4EgressID     string `json:"ipv4EgressId,omitempty"`
	HideNative       bool   `json:"hideNative"`
	Enabled          bool   `json:"enabled"`
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
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	ai := slices.IndexFunc(accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == change.AccountID })
	if ai < 0 {
		return AccountChangeResult{}, invalid
	}
	account := &accounts[ai]
	gi := slices.IndexFunc(account.Grants, func(g glivela.RouteGrant) bool { return g.ID == change.ID })
	same := gi >= 0 && account.Grants[gi].EntryID == change.EntryID && account.Grants[gi].EgressID == change.EgressID && account.Grants[gi].IPv4EgressID == change.IPv4EgressID && account.Grants[gi].HideNative == change.HideNative && account.Grants[gi].Enabled == change.Enabled
	if account.Account.DesiredRevision != change.ExpectedRevision && !(same && account.Account.DesiredRevision == change.ExpectedRevision+1) {
		return AccountChangeResult{}, invalid
	}
	if _, _, err := projectBusinessEntries(s.nodes, next, time.Now()); err != nil {
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
			if grant.EntryID != change.EntryID || grant.EgressID != change.EgressID || grant.IPv4EgressID != change.IPv4EgressID || grant.DesiredRev == math.MaxUint64 {
				return AccountChangeResult{}, invalid
			}
			grant.Enabled, grant.HideNative = change.Enabled, change.HideNative
			grant.DesiredRev++
			grant.AppliedRev, grant.RuntimeGood = 0, false
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
			grant := glivela.RouteGrant{ID: change.ID, AccountID: change.AccountID, EntryID: change.EntryID, EgressID: change.EgressID, IPv4EgressID: change.IPv4EgressID, InboundTag: next.Endpoints[ei].Reality.InboundTag, Base: account.Credentials[base], Route: credential, Mode: glivela.FixedMode, Enabled: true, HideNative: change.HideNative, DesiredRev: 1}
			if grant.Validate() != nil {
				return AccountChangeResult{}, invalid
			}
			account.Grants = append(account.Grants, grant)
			account.Credentials = append(slices.Clone(account.Credentials), credential)
			account.Usage = append(slices.Clone(account.Usage), glivela.UsageMember{CredentialID: credential.ID, Active: true})
			next.ProtocolSecrets = maps.Clone(next.ProtocolSecrets)
			next.ProtocolSecrets[credential.ID] = identity.String()
			next.TrafficCounters = maps.Clone(next.TrafficCounters)
			next.TrafficCounters[credential.ID] = glivela.ImportTrafficCounters{}
		}
		account.Account.DesiredRevision++
		var err error
		next.Plan, err = glivela.PlanImport(accounts)
		if err != nil {
			return AccountChangeResult{}, err
		}
	}
	projected, err := projectManagedRoutes(s.nodes, next, change.EntryID)
	if err != nil {
		return AccountChangeResult{}, err
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return AccountChangeResult{}, err
	}
	if err := s.commit(projected); err != nil {
		return AccountChangeResult{}, err
	}
	return s.accountChangeResult(change.AccountID, time.Now()), nil
}

// Rebuild only the selected entry's business users from the authoritative
// ledger. Transport/peer enrollment remains unchanged and must match exactly.
func projectManagedRoutes(nodes map[string]Node, material glivela.ImportMaterial, entryID string) (map[string]Node, error) {
	credentials, grants, err := effectiveBusinessCredentials(material, time.Now())
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
		for _, account := range material.Plan.Accounts {
			for _, credential := range account.Credentials {
				if credential.EntryID == entryID {
					plan.Credentials = append(plan.Credentials, credentials[credential.ID])
				}
			}
			for _, grant := range account.Grants {
				if grant.EntryID == entryID {
					plan.Grants = append(plan.Grants, grants[grant.ID])
				}
			}
		}
		used := map[string]bool{}
		for _, grant := range plan.Grants {
			used[grant.EgressID] = true
			if grant.IPv4EgressID != "" {
				used[grant.IPv4EgressID] = true
			}
		}
		// Disabled grants retain their transport until explicit resource retirement.
		for id := range used {
			if !slices.ContainsFunc(plan.Peers, func(p glivela.RoutePeer) bool { return p.EgressID == id }) {
				return nil, errors.New("control: enroll authorized entry transport before granting route")
			}
		}
		if reflect.DeepEqual(plan, node.Desired.Entry) {
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return nil, errors.New("control: entry revision exhausted")
		}
		plan.Revision++
		desired, err = NewEntryDesired(*plan, *desired.EntryNetwork)
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
