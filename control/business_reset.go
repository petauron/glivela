package control

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// ResetAccountUsage advances only this account's quota baseline. Core raw
// counters and other accounts remain untouched; the next cumulative report
// cannot replay traffic from the previous period.
func (s *Store) ResetAccountUsage(ctx context.Context, id string, expected uint64) (AccountChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return AccountChangeResult{}, err
	}
	invalid := errors.New("control: account reset refused")
	if !glivela.ValidIdentifier(id) || expected == 0 || expected == math.MaxUint64 || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return AccountChangeResult{}, invalid
	}
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	index := slices.IndexFunc(accounts, func(account glivela.ImportAccount) bool { return account.Account.ID == id })
	if index < 0 || accounts[index].Account.DesiredRevision != expected {
		return AccountChangeResult{}, invalid
	}
	accounts[index].Usage = glivela.ResetUsage(accounts[index].Usage)
	accounts[index].Account.DesiredRevision++
	var err error
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		return AccountChangeResult{}, err
	}
	next.TrafficCounters = maps.Clone(next.TrafficCounters)
	for _, credential := range accounts[index].Credentials {
		counter := next.TrafficCounters[credential.ID]
		counter.UploadBytes, counter.DownloadBytes = 0, 0
		next.TrafficCounters[credential.ID] = counter
	}
	next.ResetSchedules = maps.Clone(next.ResetSchedules)
	schedule := next.ResetSchedules[id]
	schedule.LastResetAt = time.Now().UTC().Format(time.RFC3339Nano)
	next.ResetSchedules[id] = schedule
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
