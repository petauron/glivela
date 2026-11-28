package control

import (
	"errors"
	"net/netip"

	glivela "github.com/petauron/glivela"
)

// RouteEntry binds a stable entry identity to its authenticated verifier and
// exact authorized private source. Probe batches cannot define this inventory.
type RouteEntry struct {
	CertificateID string `json:"certificateId"`
	Address       string `json:"address"`
}

var tailnetPrefix = netip.MustParsePrefix("100.64.0.0/10")

func validateRouteEntries(node Node) error {
	if node.Desired.Landing == nil {
		return errors.New("control: landing plan required for route inventory")
	}
	// A landing may be provisioned before its entry enrollment is complete,
	// including a partially enrolled inventory. No successful route acceptance
	// is allowed until every authorized source has its exact identity binding.
	if len(node.RouteEntries) == 0 {
		return nil
	}
	eihLandingUsers := 0
	for _, l := range node.Desired.Landing.EIHListeners {
		for _, u := range l.Users {
			if u.Role == "landing" {
				eihLandingUsers++
			}
		}
	}
	if len(node.RouteEntries) > len(node.Desired.Landing.Sources)+eihLandingUsers || len(node.RouteEntries) > 64 {
		return errors.New("control: entry inventory exceeds authorized sources")
	}
	sources := map[string]bool{}
	for _, source := range node.Desired.Landing.Sources {
		sources[source.Address] = true
	}
	seenCertificates := map[string]bool{}
	seenAddresses := map[string]bool{}
	for id, entry := range node.RouteEntries {
		if !glivela.ValidIdentifier(id) || !glivela.ValidIdentity(entry.CertificateID) || entry.CertificateID == node.CertificateID || seenCertificates[entry.CertificateID] || seenAddresses[entry.Address] {
			return errors.New("control: entry identity or source differs from landing policy")
		}
		if sources[entry.Address] {
			delete(sources, entry.Address)
		} else if eihLandingUsers > 0 {
			// Cut-over two-hop entries move their public source into EIHListeners
			// while retaining their authenticated tailnet RouteEntries binding.
			ip, err := netip.ParseAddr(entry.Address)
			if err != nil || ip.String() != entry.Address || !tailnetPrefix.Contains(ip) || entry.Address == node.Desired.Landing.Address {
				return errors.New("control: entry identity or source differs from landing policy")
			}
			eihLandingUsers--
		} else {
			return errors.New("control: entry identity or source differs from landing policy")
		}
		seenCertificates[entry.CertificateID] = true
		seenAddresses[entry.Address] = true
	}
	return nil
}

func completeRouteInventory(node Node, checks map[string]RouteCheck, deferred ...map[string]bool) bool {
	skip := map[string]bool{}
	if len(deferred) == 1 {
		skip = deferred[0]
	}
	if len(node.RouteEntries) == 0 || node.Desired.Landing == nil || len(node.RouteEntries) != len(node.Desired.Landing.Sources) || validateRouteEntries(node) != nil || len(checks) > len(node.RouteEntries) {
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
