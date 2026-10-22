package control

import (
	"errors"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// RouteAcceptance is a read-only gate for a single landing cutover. The caller
// reads the complete persisted entry inventory, not a caller-selected subset
// of whichever checks happened to finish. It does not commit a
// migration or remove recovery resources.
type RouteAcceptance struct {
	RuntimeReady         bool     `json:"runtimeReady"`
	RoutesPassed         bool     `json:"routesPassed"`
	Reason               string   `json:"reason"`
	DeferredEntries      []string `json:"deferredEntries,omitempty"`
	AvailabilityRevision uint64   `json:"availabilityRevision,omitempty"`
}

func (s *Store) AcceptLandingRoutes(landingID, snapshotID string, revision uint64, digest string) (RouteAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acceptLandingRoutesLocked(landingID, snapshotID, revision, digest)
}

func (s *Store) acceptLandingRoutesLocked(landingID, snapshotID string, revision uint64, digest string) (RouteAcceptance, error) {
	if !glivela.ValidIdentifier(landingID) || !glivela.ValidIdentifier(snapshotID) || revision == 0 || !glivela.ValidIdentity(digest) {
		return RouteAcceptance{}, errors.New("control: complete route acceptance identity required")
	}
	for _, node := range s.nodes {
		if node.ID != landingID {
			continue
		}
		if node.Desired.Landing == nil {
			return RouteAcceptance{}, errors.New("control: acceptance requires a landing identity")
		}
		if node.Desired.Revision != revision || node.Desired.ConfigSHA256 != digest {
			return RouteAcceptance{Reason: "revision-changed"}, nil
		}
		now := time.Now().UTC()
		if !s.availableRuntime(node, now) {
			return RouteAcceptance{Reason: "runtime-unverified"}, nil
		}
		status := RouteAcceptance{RuntimeReady: true}
		status.AvailabilityRevision = s.availability.Revision
		deferred := s.deferredEntries(node, now)
		for id := range deferred {
			status.DeferredEntries = append(status.DeferredEntries, id)
		}
		slices.Sort(status.DeferredEntries)
		if !enrolledEntriesFresh(node, s.nodes, now, deferred) {
			status.Reason = "entry-runtime-unverified"
			return status, nil
		}
		if !enrolledEntryPeersFresh(node, s.nodes, now, deferred) {
			status.Reason = "entry-route-unverified"
			return status, nil
		}
		if !completeRouteInventory(node, node.Checks, deferred) || len(deferred) == len(node.RouteEntries) {
			status.Reason = "routes-incomplete"
			return status, nil
		}
		for id, check := range node.Checks {
			if deferred[id] {
				continue
			}
			if !check.IssuedAt.After(s.recoveryBarrier(id)) || !check.IssuedAt.After(s.recoveryBarrier(node.ID)) {
				status.Reason = "recovery-unverified"
				return status, nil
			}
			if entry, found := s.nodes[check.CertificateID]; found && !entryRouteMatches(entry, check.Request) {
				status.Reason = "entry-route-policy-changed"
				return status, nil
			}
			if !routeTargetsLanding(check.Request, node) || check.Request.SnapshotID != snapshotID || check.Request.Revision != revision || check.Request.ConfigSHA256 != digest || check.Result == nil {
				status.Reason = "routes-incomplete"
				return status, nil
			}
			if validateRouteResult(check.Request, *check.Result) != nil || !check.Result.Passed {
				status.Reason = "route-failed"
				return status, nil
			}
			if check.ReceivedAt.IsZero() || check.ReceivedAt.After(now) || now.Sub(check.ReceivedAt) > 5*time.Minute {
				status.Reason = "route-expired"
				return status, nil
			}
		}
		status.RoutesPassed = true
		status.Reason = "verified"
		if len(deferred) > 0 {
			status.Reason = "verified-active-entries"
		}
		return status, nil
	}
	return RouteAcceptance{}, errors.New("control: landing is not enrolled")
}
