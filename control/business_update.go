package control

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

type AccountChangeResult struct {
	AccountID       string   `json:"accountId"`
	DesiredRevision uint64   `json:"desiredRevision,string"`
	AppliedRevision uint64   `json:"appliedRevision,string"`
	State           string   `json:"state"`
	PendingEntries  []string `json:"pendingEntries"`
}

// UpdateAccountPlan edits only the owned account plan, never credentials,
// token, usage baselines, reset schedule, historical receipts or source archive.
// The encrypted business file is authoritative. nodes.json is a recoverable
// projection, not a second business writer or a cross-file transaction log.
func (s *Store) UpdateAccountPlan(ctx context.Context, id string, expected uint64, plan glivela.AccountPlan) (AccountChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: account update refused")
	if err := ctx.Err(); err != nil {
		return AccountChangeResult{}, err
	}
	if !glivela.ValidIdentifier(id) || expected == 0 || plan.Validate() != nil || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return AccountChangeResult{}, invalid
	}
	business := s.business
	index := slices.IndexFunc(business.material.Plan.Accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == id })
	if index < 0 {
		return AccountChangeResult{}, invalid
	}
	current := business.material.Plan.Accounts[index].Account
	same := current.Plan == plan
	if current.DesiredRevision != expected && !(same && expected < math.MaxUint64 && current.DesiredRevision == expected+1) {
		return AccountChangeResult{}, invalid
	}
	next := business.material
	if !same {
		if current.DesiredRevision == math.MaxUint64 {
			return AccountChangeResult{}, invalid
		}
		accounts := slices.Clone(next.Plan.Accounts)
		accounts[index].Account.Plan = plan
		accounts[index].Account.DesiredRevision++
		var err error
		next.Plan, err = glivela.PlanImport(accounts)
		if err != nil {
			return AccountChangeResult{}, invalid
		}
	}
	projected, changed, err := projectBusinessEntries(s.nodes, next, time.Now())
	if err != nil {
		return AccountChangeResult{}, err
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return AccountChangeResult{}, err
	}
	if changed {
		if err := s.commit(projected); err != nil {
			return AccountChangeResult{}, err
		}
	}
	return s.accountChangeResult(id, time.Now()), nil
}

// Account edits and traffic observations share the same authenticated source
// commit. Projections can be rebuilt after a partial write; no second ledger
// or cross-file transaction is introduced.
func (s *Store) saveOwnedBusinessLocked(next glivela.ImportMaterial) error {
	business := s.business
	invalid := errors.New("control: owned business write refused")
	if business == nil || business.faulted || next.Ownership == nil {
		return invalid
	}
	key, err := readBusinessKey(business.keyPath)
	if err != nil {
		return invalid
	}
	defer clear(key)
	directory := filepath.Dir(s.path)
	disk, snapshot, err := readOwnedBusiness(directory, key)
	if err != nil || snapshot != business.snapshotID || !reflect.DeepEqual(disk, business.material) {
		business.faulted = true
		return errors.New("control: owned business storage changed; explicit recovery required")
	}
	if !reflect.DeepEqual(next, business.material) {
		sealed, err := glivela.SealImportMaterial(next, key, business.snapshotID)
		if err != nil {
			return invalid
		}
		raw, err := json.Marshal(stagedImport{Version: 1, SnapshotID: business.snapshotID, Sealed: sealed})
		if err != nil {
			return invalid
		}
		writeErr := replacePrivate(directory, "business.json", raw)
		// A rename may have succeeded before directory sync failed. Follow
		// independently authenticated read-back, not the return code alone.
		observed, id, readErr := readOwnedBusiness(directory, key)
		if readErr == nil && id == business.snapshotID && reflect.DeepEqual(observed, next) {
			business.material = next
		} else if readErr != nil || !reflect.DeepEqual(observed, business.material) {
			business.faulted = true
		}
		if writeErr != nil {
			return writeErr
		}
		if business.faulted || !reflect.DeepEqual(business.material, next) {
			return errors.New("control: owned business write was not confirmed")
		}
	}
	return syncBusinessDirectory(directory)
}

func effectiveBusinessCredentials(m glivela.ImportMaterial, now time.Time) (map[string]glivela.CredentialMaterial, map[string]glivela.RouteGrant, error) {
	credentials := map[string]glivela.CredentialMaterial{}
	grants := map[string]glivela.RouteGrant{}
	endpoints := map[string]bool{}
	for _, e := range m.Endpoints {
		endpoints[e.Reality.EntryID] = !e.Retired && e.QuotaAppliedEnabled && (e.TotalBytes == 0 || e.UsedBytes < e.TotalBytes)
	}
	for _, a := range m.Plan.Accounts {
		if len(a.Credentials) == 0 {
			continue
		}
		quota, err := glivela.ProjectQuota(a.Account.Plan, a.Usage)
		if err != nil {
			return nil, nil, err
		}
		active := map[string]bool{}
		for _, g := range quota.Gates {
			active[g.CredentialID] = g.Enabled
		}
		for _, c := range a.Credentials {
			c.Enabled = c.Enabled && active[c.ID] && endpoints[c.EntryID] && (a.Account.Plan.ExpiryTime == 0 || a.Account.Plan.ExpiryTime > now.UnixMilli())
			credentials[c.ID] = glivela.CredentialMaterial{Credential: c, ProtocolID: m.ProtocolSecrets[c.ID], HysteriaAuth: m.HysteriaSecrets[c.ID], HysteriaIdentity: a.HysteriaIdentities[c.ID]}
		}
		for _, g := range a.Grants {
			base, route := credentials[g.Base.ID], credentials[g.Route.ID]
			route.Credential.Enabled = route.Credential.Enabled && base.Credential.Enabled && g.Enabled
			credentials[g.Route.ID] = route
			g.Base, g.Route = base.Credential, route.Credential
			g.AppliedRev, g.RuntimeGood = 0, false
			grants[g.ID] = g
		}
	}
	// An orphan saved route credential is retained as data, never converted
	// into a native/direct authorization while waiting for a valid grant.
	routed := map[string]bool{}
	for _, g := range grants {
		routed[g.Route.ID] = true
	}
	for id, c := range credentials {
		if c.Credential.Kind == glivela.RouteCredential && !routed[id] {
			c.Credential.Enabled = false
			credentials[id] = c
		}
	}
	return credentials, grants, nil
}

func sameCredentialIdentity(a, b glivela.CredentialMaterial) bool {
	a.Credential.Enabled, b.Credential.Enabled = false, false
	return a == b
}
func sameConfiguredGrant(a, b glivela.RouteGrant) bool {
	a.Base.Enabled, b.Base.Enabled = false, false
	a.Route.Enabled, b.Route.Enabled = false, false
	return sameGrantPolicy(a, b)
}

// Preserve the source hostname as business/history data, but retain its
// previously reviewed fixed IP in the executable configuration. This does not
// resolve or choose a replacement target during migration or ordinary updates.
func pinnedImportedReality(endpoint glivela.ImportEndpoint) glivela.RealityEndpoint {
	current := endpoint.Reality
	current.Target = net.JoinHostPort(endpoint.TargetIP, "443")
	return current
}

// Reproject only enrolled resources whose identities already match the owned
// inventory. This does not create/adopt containers, infer peer identities or
// recover missing transport configuration from an old source archive.
func projectBusinessEntries(nodes map[string]Node, m glivela.ImportMaterial, now time.Time) (map[string]Node, bool, error) {
	credentials, grants, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return nil, false, err
	}
	next := make(map[string]Node, len(nodes))
	for cert, node := range nodes {
		next[cert] = node
	}
	changed := false
	for cert, node := range nodes {
		if node.Desired.Entry == nil {
			continue
		}
		desired := node.Desired.clone()
		plan := desired.Entry
		for i, current := range plan.RealityEndpoints {
			index := slices.IndexFunc(m.Endpoints, func(endpoint glivela.ImportEndpoint) bool {
				return endpoint.Reality.ID == current.ID && endpoint.Reality.EntryID == node.ID
			})
			if index < 0 {
				return nil, false, errors.New("control: entry target has no owned source")
			}
			expected := pinnedImportedReality(m.Endpoints[index])
			originalTarget := current.Target
			current.Target = expected.Target
			if !reflect.DeepEqual(current, expected) || originalTarget != expected.Target && originalTarget != m.Endpoints[index].Reality.Target {
				return nil, false, errors.New("control: entry target or TLS identity differs from owned source")
			}
			plan.RealityEndpoints[i] = expected
		}
		for i, current := range plan.Credentials {
			expected, found := credentials[current.Credential.ID]
			if !found || !sameCredentialIdentity(current, expected) {
				return nil, false, errors.New("control: entry credentials differ from owned business")
			}
			plan.Credentials[i] = expected
		}
		for i, current := range plan.Grants {
			expected, found := grants[current.ID]
			if !found || !sameConfiguredGrant(current, expected) {
				return nil, false, errors.New("control: entry grant differs from owned business")
			}
			plan.Grants[i] = expected
		}
		if reflect.DeepEqual(plan, node.Desired.Entry) {
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return nil, false, errors.New("control: entry revision exhausted")
		}
		plan.Revision++
		desired, err = NewEntryDesired(*plan, *desired.EntryNetwork)
		if err != nil {
			return nil, false, err
		}
		node.Desired, node.Receipt, node.ReportedAt, node.EntryHealthBarrierAt = desired, nil, time.Time{}, time.Time{}
		next[cert] = node
		invalidateEntryChecks(next, node.ID)
		changed = true
	}
	return next, changed, nil
}

func (s *Store) reconcileOwnedEntriesLocked(now time.Time) error {
	if s.business == nil || s.business.material.Ownership == nil {
		return nil
	}
	if s.business.faulted {
		return errors.New("control: owned business storage requires recovery")
	}
	next, changed, err := projectBusinessEntries(s.nodes, s.business.material, now)
	if err != nil {
		return err
	}
	if changed {
		return s.commit(next)
	}
	return nil
}

// This status describes entry runtime application only, not successful
// external routes, final cutover acceptance or permission to clear alarms.
func (s *Store) accountChangeResult(id string, now time.Time) AccountChangeResult {
	result := AccountChangeResult{AccountID: id, State: "saved", PendingEntries: []string{}}
	var account glivela.ImportAccount
	for _, a := range s.business.material.Plan.Accounts {
		if a.Account.ID == id {
			account = a
			result.DesiredRevision = a.Account.DesiredRevision
			result.AppliedRevision = a.Account.AppliedRevision
		}
	}
	entries := map[string]bool{}
	for _, c := range account.Credentials {
		entries[c.EntryID] = true
	}
	credentials, grants, err := effectiveBusinessCredentials(s.business.material, now)
	for id := range entries {
		found := false
		for _, node := range s.nodes {
			if node.ID == id && node.Desired.Entry != nil {
				found = err == nil && runtimeFresh(node, now)
				for _, c := range account.Credentials {
					if c.EntryID == id && !slices.Contains(node.Desired.Entry.Credentials, credentials[c.ID]) {
						found = false
					}
				}
				for _, g := range account.Grants {
					if g.EntryID == id && !slices.ContainsFunc(node.Desired.Entry.Grants, func(current glivela.RouteGrant) bool { return sameGrantPolicy(current, grants[g.ID]) }) {
						found = false
					}
				}
			}
		}
		if !found {
			result.PendingEntries = append(result.PendingEntries, id)
		}
	}
	slices.Sort(result.PendingEntries)
	if len(entries) > 0 {
		result.State = "entry-runtime-verified"
		if len(result.PendingEntries) > 0 {
			result.State = "reconciling"
		}
	}
	return result
}
