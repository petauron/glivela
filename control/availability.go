package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"time"

	glivela "github.com/petauron/glivela"
)

// Availability is an administrator's service decision, not a health result or
// a replacement ledger. Expiry permits probing, never assumes recovery.
type Availability struct {
	Revision  uint64    `json:"revision"`
	Reason    string    `json:"reason"`
	ChangedAt time.Time `json:"changedAt"`
	ResumeAt  time.Time `json:"resumeAt,omitempty"`
}

type availabilityState struct {
	Version  int                     `json:"version"`
	Revision uint64                  `json:"revision,string"`
	Nodes    map[string]Availability `json:"nodes"`
}

func (v availabilityState) validate() error {
	if v.Version != 1 || v.Revision == 0 || len(v.Nodes) > 1024 {
		return errors.New("control: invalid availability state")
	}
	for id, a := range v.Nodes {
		if a.Revision == 0 || a.Revision > v.Revision {
			return errors.New("control: invalid availability record revision")
		}
		if !glivela.ValidIdentifier(id) || (a.Reason != "traffic-exhausted" && a.Reason != "maintenance") || a.ChangedAt.IsZero() || !a.ResumeAt.IsZero() && a.ResumeAt.Before(a.ChangedAt) {
			return errors.New("control: invalid temporary suspension")
		}
	}
	return nil
}

func (s *Store) loadAvailability() error {
	path := filepath.Join(filepath.Dir(s.path), "availability.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		s.availability = availabilityState{Version: 1, Revision: 1, Nodes: map[string]Availability{}}
		return nil
	}
	raw, err := privateBackupBytes(path)
	if err != nil || len(raw) > 1<<20 || decode(bytes.NewReader(raw), &s.availability) != nil || s.availability.validate() != nil {
		return errors.New("control: availability state requires recovery")
	}
	return nil
}

// SetAvailability uses the existing admin mTLS channel and an explicit revision
// check. Unknown IDs cannot become blanket acceptance exclusions.
func (s *Store) SetAvailability(id, reason string, resumeAt time.Time, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.availability.Revision || expected == ^uint64(0) || !glivela.ValidIdentifier(id) {
		return errors.New("control: availability revision changed")
	}
	known := false
	for _, n := range s.nodes {
		known = known || n.ID == id
		_, entry := n.RouteEntries[id]
		known = known || entry
	}
	if s.business != nil {
		for _, endpoint := range s.business.material.Endpoints {
			known = known || endpoint.Reality.EntryID == id
		}
	}
	if !known {
		return errors.New("control: unknown availability identity")
	}
	now := time.Now().UTC()
	// Manual resume is a retry barrier, not deletion of the suspension proof.
	if reason == "resume" {
		old, found := s.availability.Nodes[id]
		if !found {
			return errors.New("control: node is not suspended")
		}
		reason, resumeAt = old.Reason, now
	}
	if !resumeAt.IsZero() && resumeAt.Before(now) {
		return errors.New("control: recovery time is in the past")
	}
	next := availabilityState{Version: 1, Revision: expected + 1, Nodes: maps.Clone(s.availability.Nodes)}
	next.Nodes[id] = Availability{Revision: next.Revision, Reason: reason, ChangedAt: now, ResumeAt: resumeAt.UTC()}
	if err := next.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := replacePrivate(filepath.Dir(s.path), "availability.json", raw); err != nil {
		return err
	}
	s.availability = next
	// The transitional reader consumes counters even while publication is held.
	// Never erase the receipt: a restart during suspension must not lose usage.
	nodes := s.copy()
	for cert, n := range nodes {
		if n.ID == id {
			n.PublicationSuspended = true
			nodes[cert] = n
		}
	}
	if err := s.commit(nodes); err != nil {
		return err
	}
	return nil
}

func (s *Store) effectiveAvailability(id string) (Availability, bool) {
	manual, hasManual := s.availability.Nodes[id]
	if hasManual && (manual.ResumeAt.IsZero() || time.Now().Before(manual.ResumeAt)) {
		return manual, true
	}
	for _, n := range s.nodes {
		q := n.EntryQuota
		if n.ID == id && q != nil && q.TotalBytes > 0 && q.UsedBytes >= q.TotalBytes {
			return Availability{Reason: "traffic-exhausted", ChangedAt: q.CutoverAt, ResumeAt: q.NextResetAt}, true
		}
	}
	if s.business != nil {
		for _, endpoint := range s.business.material.Endpoints {
			if endpoint.Reality.EntryID == id && endpoint.TotalBytes > 0 && endpoint.UsedBytes >= endpoint.TotalBytes {
				resume, _ := time.Parse(time.RFC3339Nano, endpoint.ResetSchedule.NextResetAt)
				return Availability{Reason: "traffic-exhausted", ResumeAt: resume}, true
			}
		}
	}
	return manual, hasManual
}

func (s *Store) effectiveAvailabilities() map[string]Availability {
	result := maps.Clone(s.availability.Nodes)
	for _, n := range s.nodes {
		if a, ok := s.effectiveAvailability(n.ID); ok {
			result[n.ID] = a
		}
	}
	if s.business != nil {
		for _, endpoint := range s.business.material.Endpoints {
			if a, ok := s.effectiveAvailability(endpoint.Reality.EntryID); ok {
				result[endpoint.Reality.EntryID] = a
			}
		}
	}
	return result
}

// Retain automatic exhaustion through recovery as well, so restart never turns
// a previously deferred inventory into a truncated or implicitly passing one.
func (s *Store) retainQuotaSuspensions(nodes map[string]Node) error {
	now := time.Now().UTC()
	next := availabilityState{Version: 1, Revision: s.availability.Revision, Nodes: maps.Clone(s.availability.Nodes)}
	if next.Nodes == nil {
		next.Nodes = map[string]Availability{}
	}
	add := func(id string, total, used int64, resume time.Time) {
		if total <= 0 || used < total || !resume.IsZero() && !resume.After(now) {
			return
		}
		if old, ok := next.Nodes[id]; ok && (old.ResumeAt.IsZero() || old.ResumeAt.After(now)) {
			return
		}
		next.Nodes[id] = Availability{Revision: next.Revision + 1, Reason: "traffic-exhausted", ChangedAt: now, ResumeAt: resume}
	}
	for _, n := range nodes {
		if q := n.EntryQuota; q != nil {
			add(n.ID, q.TotalBytes, q.UsedBytes, q.NextResetAt)
		}
	}
	if s.business != nil {
		for _, e := range s.business.material.Endpoints {
			resume, _ := time.Parse(time.RFC3339Nano, e.ResetSchedule.NextResetAt)
			add(e.Reality.EntryID, e.TotalBytes, e.UsedBytes, resume)
		}
	}
	if maps.Equal(next.Nodes, s.availability.Nodes) {
		return nil
	}
	if next.Revision == ^uint64(0) {
		return errors.New("control: availability revision exhausted")
	}
	next.Revision++
	if err := next.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := replacePrivate(filepath.Dir(s.path), "availability.json", raw); err != nil {
		return err
	}
	s.availability = next
	return nil
}

func (s *Store) suspended(id string, now time.Time) bool {
	a, ok := s.effectiveAvailability(id)
	return ok && (a.ResumeAt.IsZero() || now.Before(a.ResumeAt))
}

func (s *Store) recoveryBarrier(id string) time.Time {
	a, _ := s.effectiveAvailability(id)
	if a.ResumeAt.After(a.ChangedAt) {
		return a.ResumeAt
	}
	return a.ChangedAt
}

func (s *Store) availableRuntime(n Node, now time.Time) bool {
	barrier := s.recoveryBarrier(n.ID)
	return !s.suspended(n.ID, now) && runtimeFresh(n, now) && (barrier.IsZero() || n.ReportedAt.After(barrier) && n.Receipt != nil && (n.Desired.Entry == nil || n.Receipt.EntryHealth != nil && n.Receipt.EntryHealth.SampledAt.After(barrier)))
}

func (s *Store) deferredEntries(n Node, now time.Time) map[string]bool {
	deferred := map[string]bool{}
	for id := range n.RouteEntries {
		if s.suspended(id, now) {
			deferred[id] = true
		}
	}
	return deferred
}
