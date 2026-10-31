package control

import (
	"errors"

	glivela "github.com/petauron/glivela"
)

// RouteEntry binds a stable entry identity to its authenticated verifier and
// exact authorized private source. Probe batches cannot define this inventory.
type RouteEntry struct {
	CertificateID string `json:"certificateId"`
	Address       string `json:"address"`
}

func validateRouteEntries(node Node) error {
	if node.Desired.Landing == nil {
		return errors.New("control: landing plan required for route inventory")
	}
	// A landing may be provisioned before its entry enrollment is complete,
	// but no route checks or successful acceptance are allowed in that state.
	if len(node.RouteEntries) == 0 {
		return nil
	}
	if len(node.RouteEntries) != len(node.Desired.Landing.Sources) || len(node.RouteEntries) > 64 {
		return errors.New("control: complete authorized entry inventory required")
	}
	sources := map[string]bool{}
	for _, source := range node.Desired.Landing.Sources {
		sources[source.Address] = true
	}
	seenCertificates := map[string]bool{}
	for id, entry := range node.RouteEntries {
		if !glivela.ValidIdentifier(id) || !glivela.ValidIdentity(entry.CertificateID) || entry.CertificateID == node.CertificateID || seenCertificates[entry.CertificateID] || !sources[entry.Address] {
			return errors.New("control: entry identity or source differs from landing policy")
		}
		delete(sources, entry.Address)
		seenCertificates[entry.CertificateID] = true
	}
	return nil
}

func completeRouteInventory(node Node, checks map[string]RouteCheck, deferred ...map[string]bool) bool {
	skip := map[string]bool{}
	if len(deferred) == 1 {
		skip = deferred[0]
	}
	if len(node.RouteEntries) == 0 || validateRouteEntries(node) != nil || len(checks) > len(node.RouteEntries) {
		return false
	}
	for id, entry := range node.RouteEntries {
		check, ok := checks[id]
		if !ok && skip[id] {
			continue
		}
		if !ok || check.Request.EntryID != id || check.CertificateID != entry.CertificateID {
			return false
		}
	}
	for id := range checks {
		if _, ok := node.RouteEntries[id]; !ok {
			return false
		}
	}
	return true
}
