package control

import (
	"errors"
	"reflect"
	"time"
)

// RefreshPreparedEntryQuota retries only a never-contacted staged handover.
// The administrator must retain the old backup and stop the legacy writer
// before supplying a fresh final sample. This does not activate ownership or
// reset a ledger; the existing owner still validates and commits activation.
func (s *Store) RefreshPreparedEntryQuota(id, certificate string, expectedCutover time.Time, seed EntryQuotaSeed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	refused := errors.New("control: prepared quota refresh refused")
	node, ok := s.nodes[certificate]
	if !ok || s.business != nil || node.ID != id || node.EntryQuota == nil ||
		node.Receipt != nil || !node.ReportedAt.IsZero() || !node.EntryHealthBarrierAt.IsZero() || len(node.Checks) != 0 {
		return refused
	}
	old := node.EntryQuota
	if old.validate() != nil || old.validateDesired(node.Desired) != nil || old.Raw != nil ||
		expectedCutover.IsZero() || !old.CutoverAt.Equal(expectedCutover) {
		return refused
	}
	// Never drop forwarded usage, weaken policy, cross a reset boundary or
	// accept a stale retry. Exchange uses this same mutex and persists even a
	// first empty poll, so an already contacted node cannot pass these gates.
	for _, counter := range old.Forwarded.Counters {
		if counter.Upload != 0 || counter.Download != 0 {
			return refused
		}
	}
	now := time.Now().UTC()
	if !seed.CutoverAt.After(old.CutoverAt) || seed.CutoverAt.After(now) || now.Sub(seed.CutoverAt) > 30*time.Second ||
		seed.TotalBytes != old.TotalBytes || seed.UsedBytes < old.UsedBytes || seed.ResetDay != old.ResetDay ||
		seed.Timezone != old.Timezone || !seed.LastResetAt.Equal(old.LastResetAt) || !seed.NextResetAt.Equal(old.NextResetAt) ||
		seed.ResetDay != 0 && !seed.CutoverAt.Before(seed.NextResetAt) {
		return refused
	}
	quota, desired, err := newEntryQuota(seed, old.Base)
	if err != nil || !reflect.DeepEqual(desired, node.Desired) {
		return refused
	}
	node.EntryQuota = quota
	next := s.copy()
	next[certificate] = node
	return s.commit(next)
}
