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
	// EIHAddress records the exact public port-24000 socket owned by this
	// cut-over two-hop entry after Option A moved it out of Landing.Sources, so
	// OpenStore remains exact even when the last route is temporarily disabled.
	EIHAddress string `json:"eihAddress,omitempty"`
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
	if len(node.RouteEntries) > 64 {
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
		if entry.EIHAddress != "" {
			// Cut-over two-hop entries move their public source out of Landing.Sources
			// while retaining their exact authenticated tailnet binding and target socket.
			// Active EIH users remain checked at traffic/subscription authorization time.
			ip, err := netip.ParseAddr(entry.Address)
			if err != nil || ip.String() != entry.Address || !tailnetPrefix.Contains(ip) || entry.Address == node.Desired.Landing.Address || sources[entry.Address] ||
				!(glivela.PublicTransportIPv4(entry.EIHAddress) || glivela.PublicTransportIPv6(entry.EIHAddress)) ||
				socketOccupiedBySingleUser(*node.Desired.Landing, entry.EIHAddress) {
				return errors.New("control: entry identity or source differs from landing policy")
			}
		} else {
			if !sources[entry.Address] {
				return errors.New("control: entry identity or source differs from landing policy")
			}
			delete(sources, entry.Address)
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
