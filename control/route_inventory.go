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

func completeRouteInventory(node Node, checks map[string]RouteCheck) bool {
	if len(node.RouteEntries) == 0 || validateRouteEntries(node) != nil || len(checks) != len(node.RouteEntries) {
		return false
	}
	for id, entry := range node.RouteEntries {
		check, ok := checks[id]
		if !ok || check.Request.EntryID != id || check.CertificateID != entry.CertificateID {
			return false
		}
	}
	return true
}
