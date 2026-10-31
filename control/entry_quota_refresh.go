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
func (s *Store) RefreshPreparedEntryQuota(id, certificate string, expectedCutover time.Time, seed EntryQuotaSeed, routeHealth map[string]bool) error {
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
	// Legacy health can recover while an interrupted preparation is retained.
	// Accept only these observation flags, not a caller-supplied plan. They do
	// not constitute a native receipt or allow any Xray configuration change.
	base, expected := old.Base.clone(), node.Desired.clone()
	if len(routeHealth) != len(base.Entry.Grants) || len(expected.Entry.Grants) != len(base.Entry.Grants) {
		return refused
	}
	for i, grant := range base.Entry.Grants {
		healthy, exists := routeHealth[grant.ID]
		if !exists || expected.Entry.Grants[i].ID != grant.ID {
			return refused
		}
		base.Entry.Grants[i].RuntimeGood = healthy
		expected.Entry.Grants[i].RuntimeGood = healthy
	}
	quota, desired, err := newEntryQuota(seed, base)
	if err != nil || !reflect.DeepEqual(desired, expected) || !reflect.DeepEqual(desired.DesiredArtifact, node.Desired.DesiredArtifact) {
		return refused
	}
	node.EntryQuota = quota
	node.Desired = desired
	next := s.copy()
	next[certificate] = node
	return s.commit(next)
}
