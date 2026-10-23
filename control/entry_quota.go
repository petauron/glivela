package control

import (
	"errors"
	"math"
	"reflect"
	"time"

	glivela "github.com/petauron/glivela"
)

// EntryQuota is an enforcement projection for a staged entry handover. It is
// not an account ledger: subscription identity and cumulative billing history
// remain with the existing owner. Forwarded preserves sampled core bytes across
// quota-driven configuration revisions until that owner consumes them.
type EntryQuota struct {
	TotalBytes  int64     `json:"totalBytes,string"`
	UsedBytes   int64     `json:"usedBytes,string"`
	ResetDay    int       `json:"resetDay"`
	Timezone    string    `json:"timezone"`
	LastResetAt time.Time `json:"lastResetAt,omitempty"`
	NextResetAt time.Time `json:"nextResetAt"`
	CutoverAt   time.Time `json:"cutoverAt"`
	Base        Desired   `json:"base"`
	// TransportOrigin retains the immutable pre-transport accounting policy.
	TransportOrigin *Desired      `json:"transportOrigin,omitempty"`
	Raw             *EntryTraffic `json:"raw,omitempty"`
	Forwarded       *EntryTraffic `json:"forwarded"`
}

// EntryQuotaSeed is supplied only by the authenticated, backed-up handover.
// It contains the final period usage, not a replacement lifetime ledger.
type EntryQuotaSeed struct {
	TotalBytes  int64     `json:"totalBytes,string"`
	UsedBytes   int64     `json:"usedBytes,string"`
	ResetDay    int       `json:"resetDay"`
	Timezone    string    `json:"timezone"`
	LastResetAt time.Time `json:"lastResetAt,omitempty"`
	NextResetAt time.Time `json:"nextResetAt"`
	CutoverAt   time.Time `json:"cutoverAt"`
}

func newEntryQuota(seed EntryQuotaSeed, base Desired) (*EntryQuota, Desired, error) {
	q := &EntryQuota{TotalBytes: seed.TotalBytes, UsedBytes: seed.UsedBytes, ResetDay: seed.ResetDay, Timezone: seed.Timezone, LastResetAt: seed.LastResetAt, NextResetAt: seed.NextResetAt, CutoverAt: seed.CutoverAt, Base: base.clone(), Forwarded: &EntryTraffic{StartedAt: seed.CutoverAt.Format(time.RFC3339Nano), SampledAt: seed.CutoverAt, Counters: map[string]TrafficCounter{}}}
	if base.Entry == nil {
		return nil, Desired{}, errors.New("control: entry quota requires an entry")
	}
	for _, c := range base.Entry.Credentials {
		q.Forwarded.Counters[c.Credential.ID] = TrafficCounter{}
	}
	if err := q.validate(); err != nil {
		return nil, Desired{}, err
	}
	desired, err := NewEntryDesired(*q.plan(base.Revision), *base.EntryNetwork)
	return q, desired, err
}

func (q *EntryQuota) clone() *EntryQuota {
	if q == nil {
		return nil
	}
	next := *q
	next.Base = q.Base.clone()
	if q.TransportOrigin != nil {
		origin := q.TransportOrigin.clone()
		next.TransportOrigin = &origin
	}
	next.Raw = q.Raw.clone()
	next.Forwarded = q.Forwarded.clone()
	return &next
}

func (q *EntryQuota) validate() error {
	invalid := errors.New("control: invalid staged entry quota")
	if q == nil || q.TotalBytes < 0 || q.UsedBytes < 0 || q.ResetDay < 0 || q.ResetDay > 31 || q.CutoverAt.IsZero() || q.Base.Entry == nil || q.Base.Validate() != nil || q.Forwarded == nil {
		return invalid
	}
	if q.TransportOrigin != nil {
		origin := q.TransportOrigin.clone()
		if origin.Validate() != nil || origin.Entry == nil || origin.Revision > q.Base.Revision || len(origin.Entry.Peers) != len(q.Base.Entry.Peers) || !reflect.DeepEqual(origin.EntryNetwork, q.Base.EntryNetwork) {
			return invalid
		}
		origin.Entry.Revision = q.Base.Entry.Revision
		for i := range origin.Entry.Peers {
			origin.Entry.Peers[i].Transport = q.Base.Entry.Peers[i].Transport
		}
		if !reflect.DeepEqual(origin.Entry, q.Base.Entry) {
			return invalid
		}
	}
	if q.ResetDay == 0 {
		if !q.NextResetAt.IsZero() || !q.LastResetAt.IsZero() {
			return invalid
		}
	} else {
		location, err := time.LoadLocation(q.Timezone)
		if q.Timezone == "" || err != nil || q.NextResetAt.IsZero() || !q.LastResetAt.IsZero() && !q.NextResetAt.After(q.LastResetAt) {
			return invalid
		}
		next := q.NextResetAt.In(location)
		if !monthlyReset(next.Year(), next.Month(), q.ResetDay, location).Equal(next) {
			return invalid
		}
	}
	if validateEntryTraffic(q.Base, q.Raw) != nil || validateEntryTraffic(q.Base, q.Forwarded) != nil || q.Forwarded.StartedAt != q.CutoverAt.Format(time.RFC3339Nano) || q.Forwarded.SampledAt.Before(q.CutoverAt) {
		return invalid
	}
	if q.Raw != nil && (q.Raw.SampledAt.Before(q.CutoverAt) || !q.Raw.SampledAt.Equal(q.Forwarded.SampledAt)) {
		return invalid
	}
	if q.Raw == nil && !q.Forwarded.SampledAt.Equal(q.CutoverAt) {
		return invalid
	}
	for id, total := range q.Forwarded.Counters {
		if q.Raw == nil && (total.Upload != 0 || total.Download != 0) {
			return invalid
		}
		if q.Raw != nil {
			raw := q.Raw.Counters[id]
			if total.Upload < raw.Upload || total.Download < raw.Download {
				return invalid
			}
		}
	}
	return nil
}

// advanceEntryQuota is side-effect free. The caller must commit the resulting
// projection and desired state together before returning policy to the node.
// A cycle boundary clears only period usage, never cumulative forwarded bytes.
func advanceEntryQuota(current *EntryQuota, desired Desired, receipt *Observation, now time.Time) (*EntryQuota, Desired, error) {
	return advanceEntryQuotaWithTransportRecovery(current, desired, receipt, now, nil)
}

func advanceEntryQuotaWithTransportRecovery(current *EntryQuota, desired Desired, receipt *Observation, now time.Time, previous *Desired) (*EntryQuota, Desired, error) {
	if err := current.validate(); err != nil {
		return nil, Desired{}, err
	}
	if err := current.validateDesired(desired); err != nil {
		return nil, Desired{}, err
	}
	q := current.clone()
	if now.Before(q.CutoverAt) {
		return nil, Desired{}, errors.New("control: quota clock precedes handover")
	}
	if q.ResetDay != 0 && !q.NextResetAt.After(now) {
		location, _ := time.LoadLocation(q.Timezone)
		local := now.In(location)
		last := monthlyReset(local.Year(), local.Month(), q.ResetDay, location)
		if last.After(now) {
			last = monthlyReset(local.Year(), local.Month()-1, q.ResetDay, location)
		}
		q.UsedBytes = 0
		q.LastResetAt = last
		q.NextResetAt = monthlyReset(last.Year(), last.Month()+1, q.ResetDay, location)
	}
	verified := receipt != nil && glivela.VerifyAppliedReceipt(desired.DesiredArtifact, receipt.AppliedReceipt) == nil
	if !verified && receipt != nil && previous != nil && transportOnlyEntryChange(*previous, desired) {
		verified = glivela.VerifyAppliedReceipt(previous.DesiredArtifact, receipt.AppliedReceipt) == nil
	}
	if receipt != nil && receipt.Traffic != nil && verified {
		sample := receipt.Traffic
		if validateEntryTraffic(desired, sample) != nil || sample.SampledAt.After(now) {
			return nil, Desired{}, errors.New("control: quota traffic refused")
		}
		started, _ := time.Parse(time.RFC3339Nano, sample.StartedAt)
		if started.Before(q.CutoverAt) {
			return nil, Desired{}, errors.New("control: quota core predates handover")
		}
		if q.Raw != nil && sample.SampledAt.Equal(q.Raw.SampledAt) && !reflect.DeepEqual(sample, q.Raw) {
			return nil, Desired{}, errors.New("control: conflicting quota sample at the same time")
		}
		if sample.SampledAt.After(q.Forwarded.SampledAt) {
			if q.Raw != nil && sample.StartedAt != q.Raw.StartedAt && !started.After(q.Raw.SampledAt) {
				return nil, Desired{}, errors.New("control: quota core restart ordering refused")
			}
			for id, raw := range sample.Counters {
				delta := raw
				if q.Raw != nil && sample.StartedAt == q.Raw.StartedAt {
					prior := q.Raw.Counters[id]
					if raw.Upload < prior.Upload || raw.Download < prior.Download {
						return nil, Desired{}, errors.New("control: quota raw counter regressed")
					}
					delta.Upload -= prior.Upload
					delta.Download -= prior.Download
				}
				forwarded := q.Forwarded.Counters[id]
				if delta.Upload > math.MaxInt64-delta.Download || delta.Upload+delta.Download > math.MaxInt64-q.UsedBytes || delta.Upload > math.MaxInt64-forwarded.Upload || delta.Download > math.MaxInt64-forwarded.Download {
					return nil, Desired{}, errors.New("control: quota counter overflow")
				}
				// A delayed sample wholly preceding a reset still belongs in
				// lifetime accounting, but not in the new period's allowance.
				if !sample.SampledAt.Before(q.LastResetAt) {
					q.UsedBytes += delta.Upload + delta.Download
				}
				forwarded.Upload += delta.Upload
				forwarded.Download += delta.Download
				q.Forwarded.Counters[id] = forwarded
			}
			q.Raw = sample.clone()
			q.Forwarded.SampledAt = sample.SampledAt
		}
	}
	plan := q.plan(desired.Revision)
	if reflect.DeepEqual(plan, desired.Entry) {
		return q, desired.clone(), nil
	}
	if plan.Revision == math.MaxUint64 {
		return nil, Desired{}, errors.New("control: quota revision exhausted")
	}
	plan.Revision++
	next, err := NewEntryDesired(*plan, *q.Base.EntryNetwork)
	return q, next, err
}

func (q *EntryQuota) plan(revision uint64) *glivela.XrayPlan {
	plan := q.Base.clone().Entry
	plan.Revision = revision
	if q.TotalBytes > 0 && q.UsedBytes >= q.TotalBytes {
		for i := range plan.Credentials {
			plan.Credentials[i].Credential.Enabled = false
		}
		for i := range plan.Grants {
			plan.Grants[i].Base.Enabled = false
			plan.Grants[i].Route.Enabled = false
		}
	}
	return plan
}

func (q *EntryQuota) validateDesired(d Desired) error {
	if d.Validate() != nil || d.Revision < q.Base.Revision || !reflect.DeepEqual(q.plan(d.Revision), d.Entry) || !reflect.DeepEqual(q.Base.EntryNetwork, d.EntryNetwork) {
		return errors.New("control: quota projection differs from retained entry identity or policy")
	}
	return nil
}
