package control

import (
	"errors"
	"math"
	"time"
)

// UpgradeAccessLog advances only Xray access-log suppression. Stable identities,
// availability, credentials, quotas and all raw/forwarded/account counters are
// retained. Called under the controller directory lease before serving requests.
func (s *Store) UpgradeAccessLog() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.business != nil && s.business.faulted {
		return errors.New("control: business recovery required before access-log upgrade")
	}
	next := s.copy()
	changed := false
	for key, node := range next {
		old := node.Desired
		if old.Entry != nil && old.EntryRenderVersion&64 != 0 || old.Landing != nil && old.LandingRenderVersion&16 != 0 {
			continue
		}
		if old.Validate() != nil || old.Revision == math.MaxUint64 || node.TransportTail != nil {
			return errors.New("control: resolve retained runtime transition before access-log upgrade")
		}
		desired := old.clone()
		var err error
		if old.Entry != nil {
			version := old.EntryRenderVersion | 64
			desired.Entry.Revision++
			if node.EntryQuota != nil {
				quota := node.EntryQuota.clone()
				base := quota.Base.clone()
				base.Entry.Revision = desired.Entry.Revision
				quota.Base, err = newEntryDesiredVersion(*base.Entry, *base.EntryNetwork, version)
				if err != nil || quota.validate() != nil {
					return errors.New("control: retained quota differs during access-log upgrade")
				}
				desired.Entry = quota.plan(desired.Entry.Revision)
				node.EntryQuota = quota
			}
			desired, err = newEntryDesiredVersion(*desired.Entry, *desired.EntryNetwork, version)
		} else {
			version := old.LandingRenderVersion | 16
			desired.Landing.Revision++
			desired, err = newLandingDesiredVersion(*desired.Landing, version)
		}
		if err != nil || node.EntryQuota != nil && node.EntryQuota.validateDesired(desired) != nil {
			return errors.New("control: access-log upgrade projection rejected")
		}
		node.Desired = desired
		node.Receipt = nil
		node.Checks = nil
		node.ReportedAt = time.Time{}
		node.EntryHealthBarrierAt = time.Now().UTC()
		next[key] = node
		if desired.Entry != nil {
			invalidateEntryChecks(next, node.ID)
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return s.commit(next)
}
