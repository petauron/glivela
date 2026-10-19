package control

import (
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// Observe cumulative core samples using the imported watermarks. This accepts
// the approved sampling/restart gaps; it does not introduce a tail ledger or
// a second persistent source. Repeated and out-of-order samples add no bytes.
func (s *Store) observeBusinessTrafficLocked(node Node, receipt *Observation, now time.Time) error {
	if s.business == nil || s.business.material.Ownership == nil || s.business.faulted {
		return nil
	}
	next := s.business.material
	accounts := slices.Clone(next.Plan.Accounts)
	next.TrafficCounters = maps.Clone(next.TrafficCounters)
	next.ResetSchedules = maps.Clone(next.ResetSchedules)
	next.Endpoints = slices.Clone(next.Endpoints)
	for i := range next.Endpoints {
		endpoint := &next.Endpoints[i]
		if endpoint.ResetDay == 0 || endpoint.Retired {
			continue
		}
		zone := next.References.Services[endpoint.ServiceID].Timezone
		location, err := time.LoadLocation(zone)
		if zone == "" || err != nil {
			return errors.New("control: endpoint reset timezone required")
		}
		schedule := &endpoint.ResetSchedule
		if schedule.NextResetAt == "" {
			local := now.In(location)
			due := monthlyReset(local.Year(), local.Month(), endpoint.ResetDay, location)
			if !due.After(now) {
				due = monthlyReset(local.Year(), local.Month()+1, endpoint.ResetDay, location)
			}
			schedule.NextResetAt = due.Format(time.RFC3339Nano)
			continue
		}
		due, err := time.Parse(time.RFC3339Nano, schedule.NextResetAt)
		if err != nil {
			return errors.New("control: invalid endpoint reset schedule")
		}
		due = due.In(location)
		if !due.After(now) {
			endpoint.UsedBytes = 0
			endpoint.QuotaAppliedEnabled = true
			for !due.After(now) {
				schedule.LastResetAt = due.Format(time.RFC3339Nano)
				due = monthlyReset(due.Year(), due.Month()+1, endpoint.ResetDay, due.Location())
			}
			schedule.NextResetAt = due.Format(time.RFC3339Nano)
		}
	}
	for i := range accounts {
		account := &accounts[i]
		account.Usage = slices.Clone(account.Usage)
		schedule := next.ResetSchedules[account.Account.ID]
		days := account.Account.Plan.ResetDays
		if days == 0 {
			continue
		}
		if schedule.NextResetAt == "" {
			schedule.NextResetAt = now.AddDate(0, 0, days).Format(time.RFC3339Nano)
		} else {
			due, err := time.Parse(time.RFC3339Nano, schedule.NextResetAt)
			if err != nil {
				return errors.New("control: invalid owned reset schedule")
			}
			if !due.After(now) {
				account.Usage = glivela.ResetUsage(account.Usage)
				for _, credential := range account.Credentials {
					counter := next.TrafficCounters[credential.ID]
					counter.UploadBytes, counter.DownloadBytes = 0, 0
					next.TrafficCounters[credential.ID] = counter
				}
				// Advance from the recorded cycle, never from each retry time.
				for !due.After(now) {
					schedule.LastResetAt = due.Format(time.RFC3339Nano)
					due = due.AddDate(0, 0, days)
				}
				schedule.NextResetAt = due.Format(time.RFC3339Nano)
			}
		}
		next.ResetSchedules[account.Account.ID] = schedule
	}
	if receipt != nil && receipt.Traffic != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, receipt.AppliedReceipt) == nil {
		sample := receipt.Traffic
		if validateEntryTraffic(node.Desired, sample) != nil || sample.SampledAt.After(now) {
			return errors.New("control: entry traffic observation refused")
		}
		for i := range accounts {
			for j := range accounts[i].Usage {
				member := &accounts[i].Usage[j]
				raw, found := sample.Counters[member.CredentialID]
				if !found {
					continue // Other entries are sampled independently.
				}
				counter := next.TrafficCounters[member.CredentialID]
				if counter.ObservedAt != "" {
					observed, err := time.Parse(time.RFC3339Nano, counter.ObservedAt)
					if err != nil || !sample.SampledAt.After(observed) {
						continue
					}
				}
				var upload, download int64
				if counter.StartedAt == sample.StartedAt {
					if raw.Upload < counter.RawUploadBytes || raw.Download < counter.RawDownloadBytes {
						return errors.New("control: core traffic counter decreased without restart")
					}
					upload, download = raw.Upload-counter.RawUploadBytes, raw.Download-counter.RawDownloadBytes
				} else if counter.StartedAt != "" {
					oldStart, err := time.Parse(time.RFC3339Nano, counter.StartedAt)
					newStart, _ := time.Parse(time.RFC3339Nano, sample.StartedAt)
					if err != nil || !newStart.After(oldStart) {
						continue
					}
					upload, download = raw.Upload, raw.Download
				}
				// First post-import sample with no known source start is a new
				// watermark, not a replay of that core's entire historical total.
				if upload > math.MaxInt64-download || upload+download > math.MaxInt64-member.Observed || upload > math.MaxInt64-counter.UploadBytes || download > math.MaxInt64-counter.DownloadBytes {
					return errors.New("control: traffic counter overflow")
				}
				member.Observed += upload + download
				for k := range next.Endpoints {
					endpoint := &next.Endpoints[k]
					if endpoint.Reality.EntryID != node.ID || endpoint.Retired {
						continue
					}
					if upload+download > math.MaxInt64-endpoint.UsedBytes {
						return errors.New("control: endpoint traffic counter overflow")
					}
					endpoint.UsedBytes += upload + download
					if endpoint.TotalBytes > 0 && endpoint.UsedBytes >= endpoint.TotalBytes {
						endpoint.QuotaAppliedEnabled = false
					}
				}
				counter.UploadBytes += upload
				counter.DownloadBytes += download
				counter.RawUploadBytes, counter.RawDownloadBytes = raw.Upload, raw.Download
				counter.StartedAt = sample.StartedAt
				counter.ObservedAt = sample.SampledAt.Format(time.RFC3339Nano)
				counter.WatermarkObservedAt = counter.ObservedAt
				next.TrafficCounters[member.CredentialID] = counter
			}
		}
	}
	var err error
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(next, s.business.material) {
		return nil
	}
	return s.saveOwnedBusinessLocked(next)
}

func monthlyReset(year int, month time.Month, day int, location *time.Location) time.Time {
	first := time.Date(year, month, 1, 0, 0, 0, 0, location)
	last := first.AddDate(0, 1, -1).Day()
	if day > last {
		day = last
	}
	return time.Date(first.Year(), first.Month(), day, 0, 0, 0, 0, location)
}
