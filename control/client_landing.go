package control

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// changeSharedLandingLocked changes only client listener configuration. The
// original chain keys/ports remain encrypted for explicit forward recovery;
// neither this operation nor recovery writes counters or the server transport.
func (s *Store) changeSharedLandingLocked(c ClientChainChange) (AccountChangeResult, error) {
	invalid := errors.New("control: shared client landing change refused")
	if c.EgressIP != nil || c.ShareLanding == c.RestoreLanding || c.ID != "" || c.EntryID != "" || c.Transport != "" || c.SourceIPv6 != "" || c.ServerIPv6 != "" || c.RelayID != "" || c.RelayTransport != "" || c.RelaySourceIPv4 != "" || c.RelayServerIPv4 != "" || c.RelaySourceIPv6 != "" || c.RelayServerIPv6 != "" || c.Name != "" || c.Delete || c.Enabled || !glivela.ValidIdentifier(c.EgressID) {
		return AccountChangeResult{}, invalid
	}
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	ai := slices.IndexFunc(accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == c.AccountID })
	if ai < 0 {
		return AccountChangeResult{}, invalid
	}
	shared, exists := next.ClientLandings[c.EgressID]
	if exists && shared.AccountID != c.AccountID {
		return AccountChangeResult{}, errors.New("control: landing credential belongs to another account")
	}
	same := exists == c.ShareLanding
	if accounts[ai].Account.DesiredRevision != c.ExpectedRevision && !(same && accounts[ai].Account.DesiredRevision == c.ExpectedRevision+1) {
		return AccountChangeResult{}, invalid
	}
	found := false
	for _, chain := range next.ClientChains {
		if chain.EgressID != c.EgressID || next.DeletedClientChains[chain.ID] {
			continue
		}
		found = true
		if chain.AccountID != c.AccountID {
			return AccountChangeResult{}, errors.New("control: shared landing cannot span accounts")
		}
		if !chain.Enabled || same || c.RestoreLanding {
			continue
		}
		node, _, err := chainLanding(s.nodes, chain)
		if err != nil || !runtimeFresh(node, time.Now()) {
			return AccountChangeResult{}, errors.New("control: enrolled landing must be freshly applied before sharing")
		}
	}
	if !found {
		return AccountChangeResult{}, invalid
	}
	if c.ShareLanding {
		for _, chain := range next.ClientChains {
			if !next.DeletedClientChains[chain.ID] && chain.Relay != nil && chain.Relay.NodeID == c.EgressID && chain.Relay.Port == 24000 {
				return AccountChangeResult{}, errors.New("control: relay listener occupies shared landing port")
			}
		}
	}
	if !same {
		next.ClientLandings = maps.Clone(next.ClientLandings)
		if c.ShareLanding {
			key := make([]byte, 16)
			if _, err := rand.Read(key); err != nil {
				return AccountChangeResult{}, err
			}
			if next.ClientLandings == nil {
				next.ClientLandings = map[string]glivela.ClientLanding{}
			}
			next.ClientLandings[c.EgressID] = glivela.ClientLanding{AccountID: c.AccountID, Key: base64.StdEncoding.EncodeToString(key)}
			clear(key)
		} else {
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
		return AccountChangeResult{}, err
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
	return s.accountChangeResult(c.AccountID, time.Now()), nil
}
