package control

import (
	"errors"
	"math"
	"time"
)

// UpgradePublicEgress advances only execution policy. Stable identities,
// availability, credentials and all raw/forwarded/account counters are retained.
// Called under the controller directory lease before serving node requests.
func (s *Store) UpgradePublicEgress() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.business != nil && s.business.faulted {
		return errors.New("control: business recovery required before egress upgrade")
	}
	next := s.copy()
	changed := false
	for key, node := range next {
		old := node.Desired
		if old.Entry != nil && old.EntryRenderVersion >= 2 && old.Entry.PublicSSH == nil || old.Landing != nil && old.LandingRenderVersion >= 1 && old.Landing.PublicSSH == nil {
			continue
		}
		if old.Validate() != nil || old.Revision == math.MaxUint64 || node.TransportTail != nil {
			return errors.New("control: resolve retained runtime transition before egress upgrade")
		}
		desired := old.clone()
		var err error
		if old.Entry != nil {
			version := old.EntryRenderVersion | 2 // Preserve the existing UDP 443 bit.
			desired.Entry.Revision++
			desired.Entry.PublicSSH = nil
			if node.EntryQuota != nil {
				quota := node.EntryQuota.clone()
				base := quota.Base.clone()
				base.Entry.Revision = desired.Entry.Revision
				base.Entry.PublicSSH = nil
				quota.Base, err = newEntryDesiredVersion(*base.Entry, *base.EntryNetwork, version)
				if err != nil || quota.validate() != nil {
					return errors.New("control: retained quota differs during egress upgrade")
				}
				desired.Entry = quota.plan(desired.Entry.Revision)
				node.EntryQuota = quota
			}
			desired, err = newEntryDesiredVersion(*desired.Entry, *desired.EntryNetwork, version)
		} else {
			desired.Landing.Revision++
			desired.Landing.PublicSSH = nil
			// This migration removes legacy SSH guards only. Activating a new
			// DNS policy requires an explicit managed landing update.
			desired, err = newLandingDesiredVersion(*desired.Landing, 1)
		}
		if err != nil || node.EntryQuota != nil && node.EntryQuota.validateDesired(desired) != nil {
			return errors.New("control: egress upgrade projection rejected")
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
