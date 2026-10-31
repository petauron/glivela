package control

import (
	"errors"
	"time"
)

// Exact certificate-bound quality scheduling and idempotent report semantics.
func (s *Store) qualityExchangeState(cert string, report *qualityReport) (*QualityAssignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[cert]
	if !ok || s.entryRetiredLocked(node.ID) {
		return nil, errors.New("quality enrollment required")
	}
	h, err := s.qualityLocked()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if s.qualityPolls == nil {
		s.qualityPolls = map[string]time.Time{}
	}
	s.qualityPolls[cert] = now
	changed := false
	if report != nil {
		for i, v := range h.Checks {
			if v.ID != report.ID || v.Certificate != cert {
				continue
			}
			if v.State != "running" || now.After(v.ExpiresAt) || v.Revision != node.Desired.Revision {
				break
			}
			if report.Result.Validate(v.Address) != nil {
				return nil, errors.New("invalid quality result")
			}
			v.State = "failed"
			v.Error = report.Result.Error
			if report.Result.Report != nil {
				v.State = "succeeded"
				v.Report = report.Result.Report
				v.CheckedAt = now.Format(time.RFC3339Nano)
				v.Report.RecordObservations(now)
			}
			v.UpdatedAt = now.Format(time.RFC3339Nano)
			h.Checks[i] = v
			changed = true
			break
		}
	}
	var assignment *QualityAssignment
	for i, v := range h.Checks {
		if v.Certificate != cert || v.State != "pending" {
			continue
		}
		authorized := false
		for _, t := range s.qualityTargetsLocked() {
			if t.RuntimeID == node.ID && t.NodeID == v.NodeID && t.Address == v.Address {
				authorized = true
			}
		}
		if !authorized || v.Revision != node.Desired.Revision || now.After(v.ExpiresAt) {
			v.State = "failed"
			v.Error = "target_changed"
		} else {
			v.State = "running"
			assignment = &QualityAssignment{v.ID, v.Address, v.Revision, v.ExpiresAt}
		}
		v.UpdatedAt = now.Format(time.RFC3339Nano)
		h.Checks[i] = v
		changed = true
		break
	}
	if changed {
		if err = s.saveQualityLocked(h); err != nil {
			return nil, err
		}
	}
	return assignment, nil
}
