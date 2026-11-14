package control

import (
	"errors"
	"maps"

	glivela "github.com/petauron/glivela"
)

// The caller holds s.mu. This explicit administrator handover only retires
// verifier-only references for an owned, direct-only legacy entry. It cannot
// rotate an enrolled node, grant a route, change a landing runtime, or reuse
// observations made by the old certificate as new-entry acceptance.
func (s *Store) retireLegacyVerifierReferences(nodes map[string]Node, entry Node, previous string) error {
	refused := errors.New("control: legacy verifier handover refused")
	if !glivela.ValidIdentity(previous) || previous == entry.CertificateID || entry.Desired.Entry == nil || entry.Desired.EntryNetwork == nil || entry.EntryQuota != nil || len(entry.Desired.Entry.Grants) != 0 || len(entry.Desired.Entry.Peers) != 0 || len(entry.Desired.EntryNetwork.Peers) != 0 || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return refused
	}
	material := s.business.material
	address := ""
	for _, endpoint := range material.Endpoints {
		if endpoint.Reality.EntryID == entry.ID && !endpoint.Retired && endpoint.LegacyRetired {
			address = endpoint.Reality.ListenAddress
		}
	}
	if address == "" {
		return refused
	}
	for _, account := range material.Plan.Accounts {
		for _, grant := range account.Grants {
			if grant.EntryID == entry.ID && (!material.DeletedRoutes[grant.ID] || grant.Enabled) {
				return refused
			}
		}
	}
	for _, resource := range material.ServerTransports {
		if resource.EntryID == entry.ID {
			return refused
		}
	}
	for _, chain := range material.ClientChains {
		if chain.EntryID == entry.ID && (!material.DeletedClientChains[chain.ID] || chain.Enabled) {
			return refused
		}
	}
	found := false
	for key, node := range nodes {
		if node.ID == entry.ID || key == previous {
			return refused
		}
		reference, ok := node.RouteEntries[entry.ID]
		if !ok {
			continue
		}
		if node.Desired.Landing == nil || reference.CertificateID != previous || reference.Address != address {
			return refused
		}
		node.RouteEntries = maps.Clone(node.RouteEntries)
		delete(node.RouteEntries, entry.ID)
		node.Checks = maps.Clone(node.Checks)
		delete(node.Checks, entry.ID)
		nodes[key] = node
		found = true
	}
	if !found {
		return refused
	}
	return nil
}
