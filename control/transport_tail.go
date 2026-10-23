package control

import (
	"context"
	"errors"
	"reflect"
	"time"

	glivela "github.com/petauron/glivela"
)

// TransportTail is submitted by the enrolled entry, never by an administrator
// supplying counters on its behalf. It is accounting evidence, NOT health.
// The node must drain and fence its worker before submitting this record, and
// stop it only after acknowledgement so unacknowledged counters remain readable.
type TransportTail struct {
	Revision     uint64        `json:"revision"`
	ConfigSHA256 string        `json:"configSha256"`
	Traffic      *EntryTraffic `json:"traffic"`
}

func (t *TransportTail) validate(d Desired) error {
	if t == nil || d.Entry == nil || t.Revision != d.Revision || t.ConfigSHA256 != d.ConfigSHA256 || t.Traffic == nil || validateEntryTraffic(d, t.Traffic) != nil {
		return errors.New("control: invalid final private transport sample")
	}
	return nil
}

// Cancellation may use an expired checkpoint, but cannot authorize a switch
// or change accounting. Require the exact already-accounted, uncommitted tail.
func (s *Store) TransportCancelIntent(ctx context.Context, certificate string, tail TransportTail) (Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[certificate]
	if ctx.Err() != nil {
		return Desired{}, ctx.Err()
	}
	if !ok || s.business != nil || n.EntryQuota == nil || tail.validate(n.Desired) != nil || !reflect.DeepEqual(n.TransportTail, &tail) {
		return Desired{}, errors.New("control: cancellation checkpoint not confirmed")
	}
	return n.Desired.clone(), nil
}

// A failed activation can leave the retained worker running. Its original
// revision remains accounting evidence, never evidence of new runtime health.
func validateTransportTail(n Node, tail *TransportTail) error {
	if tail.validate(n.Desired) == nil {
		return nil
	}
	if n.TransportPrevious != nil && transportOnlyEntryChange(*n.TransportPrevious, n.Desired) && tail.validate(*n.TransportPrevious) == nil {
		return nil
	}
	return errors.New("control: final sample does not match an owned transport generation")
}

func transportOnlyEntryChange(before, after Desired) bool {
	if before.Validate() != nil || after.Validate() != nil || before.Entry == nil || after.Entry == nil || !reflect.DeepEqual(before.EntryNetwork, after.EntryNetwork) {
		return false
	}
	old := before.clone()
	old.Entry.Revision = after.Entry.Revision
	if len(old.Entry.Peers) != len(after.Entry.Peers) {
		return false
	}
	changed := 0
	for i := range old.Entry.Peers {
		if old.Entry.Peers[i].Transport != after.Entry.Peers[i].Transport {
			changed++
			old.Entry.Peers[i].Transport = after.Entry.Peers[i].Transport
		}
	}
	return changed == 1 && reflect.DeepEqual(old.Entry, after.Entry)
}

// RecordTransportTail commits the final cumulative sample once and clears
// readiness. A lost response is retried without billing twice. A conflicting
// sample cannot replace a checkpoint after the worker has stopped.
func (s *Store) RecordTransportTail(ctx context.Context, certificate string, tail TransportTail) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[certificate]
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !ok || s.business != nil || validateTransportTail(n, &tail) != nil {
		return errors.New("control: private transport tail refused")
	}
	if n.TransportTail != nil {
		if reflect.DeepEqual(n.TransportTail, &tail) {
			return nil
		}
		return errors.New("control: final sample already sealed")
	}
	now := time.Now().UTC()
	if tail.Traffic.SampledAt.After(now) || now.Sub(tail.Traffic.SampledAt) > time.Minute {
		return errors.New("control: final sample is not current")
	}
	if n.EntryQuota == nil {
		// Older unlimited entries forward raw generations. Preserve the last
		// acknowledged generation/counters as the existing projection's origin,
		// so its owner consumes only the remaining delta, never a zero baseline.
		if n.Receipt == nil || glivela.VerifyAppliedReceipt(n.Desired.DesiredArtifact, n.Receipt.AppliedReceipt) != nil || n.Receipt.Traffic == nil || validateEntryTraffic(n.Desired, n.Receipt.Traffic) != nil || tail.validate(n.Desired) != nil {
			return errors.New("control: unlimited entry accounting origin unavailable")
		}
		prior := n.Receipt.Traffic
		started, err := time.Parse(time.RFC3339Nano, prior.StartedAt)
		if err != nil || prior.StartedAt != tail.Traffic.StartedAt || tail.Traffic.SampledAt.Before(prior.SampledAt) {
			return errors.New("control: unlimited entry accounting generation changed")
		}
		for id, counter := range prior.Counters {
			final := tail.Traffic.Counters[id]
			if final.Upload < counter.Upload || final.Download < counter.Download {
				return errors.New("control: unlimited entry counters decreased")
			}
		}
		origin := n.Desired.clone()
		n.EntryQuota = &EntryQuota{CutoverAt: started, Base: n.Desired.clone(), TransportOrigin: &origin, Raw: prior.clone(), Forwarded: prior.clone()}
	}
	// This receipt is used ONLY by the existing cumulative accounting reducer.
	// It is never stored or exposed as evidence that the stopped worker is ready.
	receipt := &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: tail.Revision, ConfigSHA256: tail.ConfigSHA256, RuntimeReady: true}, Traffic: tail.Traffic}
	q, desired, err := advanceEntryQuotaWithTransportRecovery(n.EntryQuota, n.Desired, receipt, now, n.TransportPrevious)
	if err != nil {
		return err
	}
	// A quota/reset projection racing this checkpoint needs ordinary handling
	// first; do not publish a transport checkpoint against a different revision.
	if !reflect.DeepEqual(desired, n.Desired) {
		return errors.New("control: quota policy changed before final checkpoint")
	}
	if !reflect.DeepEqual(q.Raw, tail.Traffic) {
		return errors.New("control: final sample did not advance retained accounting")
	}
	tail.Traffic = tail.Traffic.clone()
	n.EntryQuota, n.TransportTail = q, &tail
	n.Receipt = nil
	n.ReportedAt = now
	n.EntryHealthBarrierAt = now
	n.PublicationSuspended = true
	next := s.copy()
	next[certificate] = n
	return s.commit(next)
}

// ResumeTransportPreparation cancels an UNCOMMITTED switch after the node
// restores its original worker. It never restores a database or old counters.
// Once the paired transaction changed desired state this operation refuses;
// restoring a committed pair requires a new, monotonic transport transaction.
func (s *Store) ResumeTransportPreparation(ctx context.Context, certificate string, actual Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[certificate]
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := time.Now().UTC()
	if !ok || s.business != nil || n.TransportTail == nil || n.EntryQuota == nil ||
		glivela.VerifyAppliedReceipt(n.Desired.DesiredArtifact, actual.AppliedReceipt) != nil ||
		actual.Traffic == nil || validateEntryTraffic(n.Desired, actual.Traffic) != nil ||
		validateEntryHealth(n.Desired, actual.EntryHealth) != nil ||
		actual.Traffic.SampledAt.After(now) || now.Sub(actual.Traffic.SampledAt) > time.Minute ||
		!actual.Traffic.SampledAt.After(n.TransportTail.Traffic.SampledAt) ||
		actual.EntryHealth != nil && actual.EntryHealth.SampledAt.After(now) {
		return errors.New("control: original worker restoration not verified")
	}
	q, desired, err := advanceEntryQuota(n.EntryQuota, n.Desired, &actual, now)
	if err != nil {
		return err
	}
	n.EntryQuota, n.Desired = q, desired
	n.TransportTail = nil
	// Let the next normal exchange establish health and fresh route leases.
	// A restore response is not a double-hop acceptance result.
	n.Receipt = nil
	n.ReportedAt, n.EntryHealthBarrierAt = now, now
	n.PublicationSuspended = true
	next := s.copy()
	next[certificate] = n
	return s.commit(next)
}
