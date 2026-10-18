package control

import (
	"errors"
	"time"

	glivela "github.com/petauron/glivela"
)

// RouteAcceptance is a read-only gate for a single landing cutover. The caller
// reads the complete persisted entry inventory, not a caller-selected subset
// of whichever checks happened to finish. It does not commit a
// migration or remove recovery resources.
type RouteAcceptance struct {
	RuntimeReady bool   `json:"runtimeReady"`
	RoutesPassed bool   `json:"routesPassed"`
	Reason       string `json:"reason"`
}

func (s *Store) AcceptLandingRoutes(landingID, snapshotID string, revision uint64, digest string) (RouteAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !glivela.ValidIdentifier(landingID) || !glivela.ValidIdentifier(snapshotID) || revision == 0 || !glivela.ValidIdentity(digest) {
		return RouteAcceptance{}, errors.New("control: complete route acceptance identity required")
	}
	for _, node := range s.nodes {
		if node.ID != landingID {
			continue
		}
		if node.Desired.Revision != revision || node.Desired.ConfigSHA256 != digest {
			return RouteAcceptance{Reason: "revision-changed"}, nil
		}
		now := time.Now().UTC()
		if !runtimeFresh(node, now) {
			return RouteAcceptance{Reason: "runtime-unverified"}, nil
		}
		status := RouteAcceptance{RuntimeReady: true}
		if !completeRouteInventory(node, node.Checks) {
			status.Reason = "routes-incomplete"
			return status, nil
		}
		for _, check := range node.Checks {
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
		return status, nil
	}
	return RouteAcceptance{}, errors.New("control: landing is not enrolled")
}
