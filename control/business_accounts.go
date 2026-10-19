package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

type AccountCreated struct {
	AccountChangeResult
	SubscriptionToken string `json:"subscriptionToken"`
}

// The administrator supplies a stable request/account ID. Retrying the same
// creation returns the original token and identities, never another account.
func (s *Store) CreateAccount(ctx context.Context, id, name string, plan glivela.AccountPlan, entries []string) (AccountCreated, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: account creation refused")
	account := glivela.Account{ID: id, DisplayName: name, Plan: plan, DesiredRevision: 1}
	if ctx.Err() != nil {
		return AccountCreated{}, ctx.Err()
	}
	if account.Validate() != nil || len(entries) == 0 || len(entries) > 1024 || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return AccountCreated{}, invalid
	}
	selected := map[string]glivela.ImportEndpoint{}
	for i, entry := range entries {
		if slices.Contains(entries[:i], entry) {
			return AccountCreated{}, invalid
		}
		index := slices.IndexFunc(s.business.material.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == entry && !e.Retired })
		if index < 0 {
			return AccountCreated{}, invalid
		}
		selected[entry] = s.business.material.Endpoints[index]
	}
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	index := slices.IndexFunc(accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == id })
	if index >= 0 {
		previous := accounts[index]
		if previous.Account.DisplayName != name || previous.Account.Plan != plan || len(previous.Credentials) != len(entries) || len(previous.Grants) != 0 {
			return AccountCreated{}, invalid
		}
		for _, credential := range previous.Credentials {
			if _, found := selected[credential.EntryID]; !found || credential.Kind != glivela.NativeCredential {
				return AccountCreated{}, invalid
			}
		}
	} else {
		token, err := accountSecret()
		if err != nil {
			return AccountCreated{}, err
		}
		item := glivela.ImportAccount{Account: account, SubscriptionTokenFingerprint: glivela.SubscriptionTokenFingerprint(token), HysteriaIdentities: map[string]string{}}
		next.SubscriptionTokens = make(map[string]string, len(next.SubscriptionTokens)+1)
		maps.Copy(next.SubscriptionTokens, s.business.material.SubscriptionTokens)
		next.ProtocolSecrets = make(map[string]string, len(next.ProtocolSecrets)+len(entries))
		maps.Copy(next.ProtocolSecrets, s.business.material.ProtocolSecrets)
		next.HysteriaSecrets = make(map[string]string, len(next.HysteriaSecrets)+len(entries))
		maps.Copy(next.HysteriaSecrets, s.business.material.HysteriaSecrets)
		next.TrafficCounters = make(map[string]glivela.ImportTrafficCounters, len(next.TrafficCounters)+len(entries))
		maps.Copy(next.TrafficCounters, s.business.material.TrafficCounters)
		next.ResetSchedules = make(map[string]glivela.ImportResetSchedule, len(next.ResetSchedules)+1)
		maps.Copy(next.ResetSchedules, s.business.material.ResetSchedules)
		next.SubscriptionTokens[id] = token
		next.ResetSchedules[id] = glivela.ImportResetSchedule{}
		for _, entry := range entries {
			identity, err := uuid.NewRandom()
			if err != nil {
				return AccountCreated{}, err
			}
			credentialID, err := uuid.NewRandom()
			if err != nil {
				return AccountCreated{}, err
			}
			credential := glivela.Credential{ID: credentialID.String(), AccountID: id, EntryID: entry, Kind: glivela.NativeCredential, User: credentialID.String(), Identity: glivela.Identity(identity.String()), Enabled: true}
			item.Credentials = append(item.Credentials, credential)
			item.Usage = append(item.Usage, glivela.UsageMember{CredentialID: credential.ID, Active: true})
			next.ProtocolSecrets[credential.ID] = identity.String()
			next.TrafficCounters[credential.ID] = glivela.ImportTrafficCounters{}
			if selected[entry].HysteriaEnabled && selected[entry].Hysteria != nil {
				secret, err := accountSecret()
				if err != nil {
					return AccountCreated{}, err
				}
				next.HysteriaSecrets[credential.ID] = secret
				item.HysteriaIdentities[credential.ID] = glivela.Identity(secret)
			}
		}
		accounts = append(accounts, item)
		next.Plan, err = glivela.PlanImport(accounts)
		if err != nil {
			return AccountCreated{}, err
		}
	}
	projected, err := projectAccountCreation(s.nodes, next, id)
	if err != nil {
		return AccountCreated{}, err
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return AccountCreated{}, err
	}
	// Lost projection writes are retried using the SAME request ID/material.
	// The subscription gate remains unverified until the actual entry applies.
	if err := s.commit(projected); err != nil {
		return AccountCreated{}, err
	}
	return AccountCreated{AccountChangeResult: s.accountChangeResult(id, time.Now()), SubscriptionToken: s.business.material.SubscriptionTokens[id]}, nil
}

func projectAccountCreation(nodes map[string]Node, material glivela.ImportMaterial, id string) (map[string]Node, error) {
	credentials, _, err := effectiveBusinessCredentials(material, time.Now())
	if err != nil {
		return nil, err
	}
	next := maps.Clone(nodes)
	for certificate, node := range nodes {
		if node.Desired.Entry == nil {
			continue
		}
		desired := node.Desired.clone()
		added := false
		for _, account := range material.Plan.Accounts {
			if account.Account.ID != id {
				continue
			}
			for _, credential := range account.Credentials {
				if credential.EntryID != node.ID || slices.ContainsFunc(desired.Entry.Credentials, func(c glivela.CredentialMaterial) bool { return c.Credential.ID == credential.ID }) {
					continue
				}
				desired.Entry.Credentials = append(desired.Entry.Credentials, credentials[credential.ID])
				added = true
			}
		}
		if !added {
			continue
		}
		if desired.Entry.Revision == math.MaxUint64 {
			return nil, errors.New("control: entry revision exhausted")
		}
		desired.Entry.Revision++
		desired, err = NewEntryDesired(*desired.Entry, *desired.EntryNetwork)
		if err != nil {
			return nil, err
		}
		node.Desired, node.Receipt, node.ReportedAt, node.EntryHealthBarrierAt = desired, nil, time.Time{}, time.Time{}
		next[certificate] = node
		invalidateEntryChecks(next, node.ID)
	}
	projected, _, err := projectBusinessEntries(next, material, time.Now())
	return projected, err
}

func accountSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	defer clear(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
