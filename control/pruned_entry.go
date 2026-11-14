package control

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

type PruneRetiredEntryChange struct {
	ID               string `json:"id"`
	CertificateID    string `json:"certificateId"`
	ExpectedRevision uint64 `json:"expectedRevision,string"`
	Confirmation     string `json:"confirmation"`
}

// PruneRetiredEntry removes only an already-retired offline execution source.
// Its accounting inventory is unchanged. Persist the revocation before removing
// the recoverable nodes.json projection; a retry or restart finishes that step.
func (s *Store) PruneRetiredEntry(ctx context.Context, change PruneRetiredEntryChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bad := errors.New("control: retired entry cleanup refused")
	if ctx.Err() != nil || !glivela.ValidIdentifier(change.ID) || !glivela.ValidIdentity(change.CertificateID) || change.ExpectedRevision == 0 || change.Confirmation != change.ID || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return bad
	}
	next := s.business.material
	if old, retry := next.PrunedEntries[change.ID]; retry {
		if old.CertificateID != change.CertificateID || old.Revision != change.ExpectedRevision {
			return bad
		}
	} else {
		index := slices.IndexFunc(next.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == change.ID })
		if index < 0 || !next.Endpoints[index].Retired || realityChangePending(next.Endpoints[index]) {
			return bad
		}
		node, found := s.nodes[change.CertificateID]
		now := time.Now().UTC()
		if !found || node.ID != change.ID || node.Desired.Entry == nil || node.Desired.Revision != change.ExpectedRevision || node.TransportTail != nil || node.ReportedAt.After(now.Add(-5*time.Minute)) || s.speedHub != nil && s.speedHub.online(change.CertificateID) || s.speedFault {
			return bad
		}
		for _, job := range s.speedJobs {
			if (job.Request.EntryID == change.ID || job.Request.LandingID == change.ID) && !job.View.CleanupConfirmed && now.Before(job.View.StartedAt.Add(speedLease+15*time.Second)) {
				return bad
			}
		}
		if node.Network != nil && node.Network.Command != nil && now.Before(node.Network.Command.ExpiresAt) && (node.Network.Result == nil || node.Network.Result.ID != node.Network.Command.ID) {
			return bad
		}
		e := next.Endpoints[index]
		next.PrunedEntries = maps.Clone(next.PrunedEntries)
		if next.PrunedEntries == nil {
			next.PrunedEntries = map[string]glivela.PrunedEntry{}
		}
		next.PrunedEntries[change.ID] = glivela.PrunedEntry{CertificateID: change.CertificateID, Revision: change.ExpectedRevision, EndpointID: e.Reality.ID, ServiceID: e.ServiceID, InboundTag: e.Reality.InboundTag, TotalBytes: e.TotalBytes, UsedBytes: e.UsedBytes, ResetDay: e.ResetDay, ResetSchedule: e.ResetSchedule, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt}
		next.Endpoints = slices.Delete(slices.Clone(next.Endpoints), index, index+1)
	}
	if next.Validate() != nil {
		return bad
	}
	projected, changed, err := projectBusinessEntries(s.nodes, next, time.Now())
	if err != nil {
		return err
	}
	// No implicit reconciliation or updates to any surviving node are allowed.
	for cert, node := range s.nodes {
		if node.ID != change.ID && !reflect.DeepEqual(node, projected[cert]) {
			return bad
		}
	}
	if len(projected) != len(s.nodes) && len(projected) != len(s.nodes)-1 {
		return bad
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return err
	}
	if changed {
		return s.commit(projected)
	}
	return nil
}

func projectPrunedEntries(nodes map[string]Node, m glivela.ImportMaterial) (map[string]Node, bool, error) {
	next := maps.Clone(nodes)
	changed := false
	for cert, node := range nodes {
		for id, retired := range m.PrunedEntries {
			if node.ID != id && node.CertificateID != retired.CertificateID {
				continue
			}
			if node.ID != id || cert != retired.CertificateID || node.Desired.Entry == nil || node.Desired.Revision != retired.Revision {
				return nil, false, errors.New("control: pruned enrollment identity differs")
			}
			delete(next, cert)
			changed = true
		}
	}
	return next, changed, nil
}
