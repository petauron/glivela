package control

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// entryRetired only interprets the existing owned endpoint policy. It does not
// delete the enrollment, account credentials, route records or ledger.
func entryRetired(m glivela.ImportMaterial, id string) bool {
	if _, pruned := m.PrunedEntries[id]; pruned {
		return true
	}
	if _, retired := m.RetiredLandings[id]; retired {
		return true
	}
	return slices.ContainsFunc(m.Endpoints, func(e glivela.ImportEndpoint) bool {
		return e.Reality.EntryID == id && e.Retired
	})
}

// Callers hold s.mu while accessing owned business state.
func (s *Store) entryRetiredLocked(id string) bool {
	return s.business != nil && entryRetired(s.business.material, id)
}

type RetireEntryChange struct {
	ID                           string `json:"id"`
	ExpectedRevision             uint64 `json:"expectedRevision,string"`
	ExpectedAvailabilityRevision uint64 `json:"expectedAvailabilityRevision,string"`
}

// RetireEntry withdraws an explicitly suspended offline entry from the owned
// control inventory. It does not claim to stop or clean the unreachable host.
// Active client listeners must first be retired through the normal landing
// workflow; no other node may receive a changed desired configuration here.
func (s *Store) RetireEntry(ctx context.Context, change RetireEntryChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	refused := errors.New("control: entry retirement refused")
	if err := ctx.Err(); err != nil {
		return err
	}
	if !glivela.ValidIdentifier(change.ID) || change.ExpectedRevision == 0 ||
		change.ExpectedAvailabilityRevision != s.availability.Revision ||
		s.business == nil || s.business.faulted || s.business.material.Ownership == nil ||
		s.entryRetiredLocked(change.ID) {
		return refused
	}
	pause, ok := s.availability.Nodes[change.ID]
	if !ok || pause.Reason != "maintenance" || !pause.ResumeAt.IsZero() {
		return refused
	}
	now := time.Now().UTC()
	found := false
	for certificate, node := range s.nodes {
		if node.ID != change.ID {
			continue
		}
		if found || node.Desired.Entry == nil || node.Desired.Revision != change.ExpectedRevision ||
			node.TransportTail != nil || node.ReportedAt.IsZero() || node.ReportedAt.After(now) ||
			now.Sub(node.ReportedAt) < 5*time.Minute || s.speedHub != nil && s.speedHub.online(certificate) {
			return refused
		}
		if node.Network != nil && node.Network.Command != nil && now.Before(node.Network.Command.ExpiresAt) && (node.Network.Result == nil || node.Network.Result.ID != node.Network.Command.ID) {
			return refused
		}
		found = true
	}
	if !found || s.speedFault {
		return refused
	}
	for _, job := range s.speedJobs {
		if job.Request.EntryID == change.ID && !job.View.CleanupConfirmed && now.Before(job.View.StartedAt.Add(speedLease+15*time.Second)) {
			return refused
		}
	}
	next := s.business.material
	for _, resource := range next.ServerTransports {
		if resource.EntryID == change.ID || resource.EgressID == change.ID || resource.Peer.Relay != nil && resource.Peer.Relay.NodeID == change.ID {
			return errors.New("control: retire owned server transport first")
		}
	}
	for _, chain := range next.ClientChains {
		if chain.EntryID != change.ID {
			continue
		}
		if chain.Enabled {
			return errors.New("control: retire active client chain first")
		}
		if !clientChainDeletionReady(s.nodes, next, chain, now) {
			return errors.New("control: client chain listener retirement not verified")
		}
	}
	next.Endpoints = slices.Clone(next.Endpoints)
	index := slices.IndexFunc(next.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == change.ID })
	if index < 0 || realityChangePending(next.Endpoints[index]) {
		return refused
	}
	next.Endpoints[index].Retired = true
	next.Endpoints[index].UpdatedAt = now.Format(time.RFC3339Nano)
	accounts := slices.Clone(next.Plan.Accounts)
	for i := range accounts {
		grants := slices.Clone(accounts[i].Grants)
		changed := false
		for j := range grants {
			if grants[j].EntryID != change.ID || !grants[j].Enabled {
				continue
			}
			if grants[j].DesiredRev == math.MaxUint64 {
				return refused
			}
			grants[j].Enabled = false
			grants[j].DesiredRev++
			changed = true
		}
		if changed {
			if accounts[i].Account.DesiredRevision == math.MaxUint64 {
				return refused
			}
			accounts[i].Grants = grants
			accounts[i].Account.DesiredRevision++
		}
	}
	var err error
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil || next.Validate() != nil {
		return refused
	}
	projected, _, err := projectBusinessEntries(s.nodes, next, now)
	if err != nil || !reflect.DeepEqual(projected, s.nodes) {
		return errors.New("control: retirement would change another runtime")
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return err
	}
	return nil
}
