package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"sort"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type RouteCheck struct {
	CertificateID string            `json:"certificateId"`
	Request       RouteProbe        `json:"request"`
	IssuedAt      time.Time         `json:"issuedAt"`
	Result        *RouteProbeResult `json:"result,omitempty"`
	ReceivedAt    time.Time         `json:"receivedAt,omitempty"`
}

func runtimeFresh(node Node, now time.Time) bool {
	return node.Receipt != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, *node.Receipt) == nil && !node.ReportedAt.IsZero() && !node.ReportedAt.After(now) && now.Sub(node.ReportedAt) <= time.Minute
}

func routeTargetsLanding(p RouteProbe, node Node) bool {
	endpoint, err := netip.ParseAddrPort(p.SOCKSAddress)
	address, addressErr := netip.ParseAddr(node.Desired.Landing.Address)
	return err == nil && addressErr == nil && endpoint.Addr() == address && endpoint.Port() == landing.SOCKSPort &&
		p.LandingID == node.ID && p.Revision == node.Desired.Revision && p.ConfigSHA256 == node.Desired.ConfigSHA256
}

// AssignRouteChecks atomically fixes the complete entry inventory for one
// landing verification. A retry replaces the whole attempt, never a subset of
// its results. This administrative operation is not exposed to nodes.
func (s *Store) AssignRouteChecks(assignments []RouteCheck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(assignments) == 0 || len(assignments) > 64 {
		return errors.New("control: complete route inventory required")
	}
	request := assignments[0].Request
	checks := make(map[string]RouteCheck, len(assignments))
	now := time.Now().UTC()
	for _, assignment := range assignments {
		p := assignment.Request
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		p.AttemptID = hex.EncodeToString(nonce[:])
		if !glivela.ValidIdentity(assignment.CertificateID) || p.Validate() != nil || assignment.Result != nil || p.LandingID != request.LandingID || p.SnapshotID != request.SnapshotID || p.Revision != request.Revision || p.ConfigSHA256 != request.ConfigSHA256 {
			return errors.New("control: invalid route inventory")
		}
		if _, exists := checks[p.EntryID]; exists {
			return errors.New("control: duplicate entry")
		}
		checks[p.EntryID] = RouteCheck{CertificateID: assignment.CertificateID, Request: p, IssuedAt: now}
	}
	for key, node := range s.nodes {
		if node.ID != request.LandingID {
			continue
		}
		if node.Desired.Revision != request.Revision || node.Desired.ConfigSHA256 != request.ConfigSHA256 {
			return errors.New("control: route assignment is stale")
		}
		for _, check := range checks {
			if !routeTargetsLanding(check.Request, node) {
				return errors.New("control: route endpoint differs from assigned landing")
			}
		}
		if !runtimeFresh(node, time.Now().UTC()) {
			return errors.New("control: applied runtime proof required before route check")
		}
		node.Checks = checks
		next := s.copy()
		next[key] = node
		return s.commit(next)
	}
	return errors.New("control: landing is not enrolled")
}

func validateRouteResult(p RouteProbe, r RouteProbeResult) error {
	if r.AttemptID != p.AttemptID || r.SnapshotID != p.SnapshotID || r.EntryID != p.EntryID || r.LandingID != p.LandingID || r.Revision != p.Revision || r.ConfigSHA256 != p.ConfigSHA256 || r.CheckedAt.IsZero() || r.DurationMillis < 0 || r.DurationMillis > 15000 {
		return errors.New("control: route result does not match assignment")
	}
	if r.Passed {
		observed, err := netip.ParseAddr(r.ObservedExit)
		expected, expectedErr := netip.ParseAddr(p.ExpectedExit)
		if !r.TLSVerified || r.HTTPStatus != 200 || err != nil || expectedErr != nil || observed != expected || r.Failure != "" {
			return errors.New("control: incomplete route success")
		}
	} else {
		switch r.Failure {
		case "connect-or-tls", "http-status", "exit-response", "exit-mismatch":
		default:
			return errors.New("control: invalid route failure")
		}
	}
	return nil
}

// RouteExchange trusts only the peer certificate extracted from verified mTLS.
// Reports never identify their own authorized certificate. Completed attempts
// are idempotent, but changed replays and previous revisions are rejected.
func (s *Store) RouteExchange(ctx context.Context, certificate string, report *RouteProbeResult) ([]RouteProbe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !glivela.ValidIdentity(certificate) {
		return nil, errors.New("control: invalid route identity")
	}
	now := time.Now().UTC()
	if report != nil {
		found := false
		for key, node := range s.nodes {
			if node.ID != report.LandingID {
				continue
			}
			check, ok := node.Checks[report.EntryID]
			if !ok || check.CertificateID != certificate || !routeTargetsLanding(check.Request, node) || validateRouteResult(check.Request, *report) != nil || node.Desired.Revision != report.Revision || node.Desired.ConfigSHA256 != report.ConfigSHA256 {
				return nil, errors.New("control: route report refused")
			}
			if check.Result != nil {
				if !reflect.DeepEqual(*check.Result, *report) {
					return nil, errors.New("control: route attempt already completed")
				}
				found = true
				break
			}
			if !runtimeFresh(node, now) {
				return nil, errors.New("control: applied runtime proof lost")
			}
			if now.Sub(check.IssuedAt) > 5*time.Minute || report.CheckedAt.Before(check.IssuedAt.Add(-5*time.Second)) || report.CheckedAt.After(now.Add(5*time.Second)) {
				return nil, errors.New("control: route attempt expired")
			}
			copyReport := *report
			check.Result = &copyReport
			check.ReceivedAt = now
			node.Checks = maps.Clone(node.Checks)
			node.Checks[report.EntryID] = check
			next := s.copy()
			next[key] = node
			if err := s.commit(next); err != nil {
				return nil, err
			}
			found = true
			break
		}
		if !found {
			return nil, errors.New("control: unknown route report")
		}
	}
	var pending []RouteProbe
	for _, node := range s.nodes {
		if !runtimeFresh(node, now) {
			continue
		}
		for _, check := range node.Checks {
			if check.CertificateID == certificate && check.Result == nil && now.Sub(check.IssuedAt) <= 5*time.Minute && routeTargetsLanding(check.Request, node) {
				pending = append(pending, check.Request)
			}
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].AttemptID < pending[j].AttemptID })
	return pending, nil
}
