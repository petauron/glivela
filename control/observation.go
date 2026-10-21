package control

import (
	"errors"
	"maps"
	"reflect"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// Observation is Glivela's direct node report. The base runtime receipt alone
// never proves that one of an entry's landing gates is currently usable.
type Observation struct {
	glivela.AppliedReceipt
	EntryHealth *EntryHealthReport `json:"entryHealth,omitempty"`
	Traffic     *EntryTraffic      `json:"traffic,omitempty"`
}

type EntryHealthReport struct {
	SampledAt time.Time                       `json:"sampledAt"`
	Source    *landing.PeerIdentity           `json:"source,omitempty"`
	Peers     map[string]EntryPeerObservation `json:"peers"`
}

type EntryPeerObservation struct {
	Identity landing.PeerIdentity  `json:"identity"`
	Status   landing.MonitorStatus `json:"status"`
}

func (o Observation) clone() Observation {
	o.Traffic = o.Traffic.clone()
	if o.EntryHealth != nil {
		h := *o.EntryHealth
		h.Peers = maps.Clone(h.Peers)
		if h.Source != nil {
			source := *h.Source
			h.Source = &source
		}
		o.EntryHealth = &h
	}
	return o
}

// Validate shape independently of wall-clock freshness, so old evidence can
// remain as history without being eligible to clear a current warning.
func validateEntryHealth(desired Desired, health *EntryHealthReport) error {
	if health == nil {
		return nil
	}
	invalid := errors.New("control: entry observation differs from assigned policy")
	if health.SampledAt.IsZero() || desired.Entry == nil || desired.EntryNetwork == nil || !reflect.DeepEqual(health.Source, desired.EntryNetwork.Source) || len(health.Peers) != len(desired.EntryNetwork.Peers) {
		return invalid
	}
	for _, peer := range desired.EntryNetwork.Peers {
		observation, found := health.Peers[peer.EgressID]
		status := observation.Status
		if !found || observation.Identity != peer.Identity || status.Revision != desired.Revision || status.CheckedAt.After(health.SampledAt) || status.DurationMS < 0 || status.DurationMS > 30000 || len(status.Reason) > 128 || strings.ContainsAny(status.Reason, "\x00\r\n") {
			return invalid
		}
		switch status.State {
		case "blocked":
			if !status.AllowedUntil.IsZero() {
				return invalid
			}
		case "healthy", "degraded":
			ready := status.State == "healthy" && status.Stage == "complete" && status.Reason == "direct_and_business_ready" && status.ConsecutiveFailures == 0
			grace := status.State == "degraded" && status.Reason == "network_failure_grace" && status.ConsecutiveFailures > 0 && status.ConsecutiveFailures < landing.FailureThreshold && status.ConsecutiveSuccesses == 0
			if (!ready && !grace) || status.LinkState != "direct" || !status.TCP || status.UDP || status.ExitIP != peer.ExpectedExit ||
				status.StartedAt.IsZero() || status.CheckedAt.Before(status.StartedAt) || status.CheckedAt.Sub(status.StartedAt) > landing.AllowLifetime ||
				status.LastHealthyAt.IsZero() || status.LastHealthyAt.After(status.CheckedAt) || status.CheckedAt.Sub(status.LastHealthyAt) >= landing.BusinessLifetime ||
				status.SecurityCheckedAt.Before(status.StartedAt) || status.SecurityCheckedAt.After(status.CheckedAt) ||
				!status.AllowedUntil.After(status.CheckedAt) || status.AllowedUntil.After(status.SecurityCheckedAt.Add(landing.AllowLifetime)) || status.AllowedUntil.After(status.LastHealthyAt.Add(landing.BusinessLifetime)) {
				return invalid
			}
		default:
			return invalid
		}
	}
	return nil
}

// Stored pre-hysteresis observations are retained as historical evidence only.
// Validate their original bounded shape without upgrading the stored proof:
// live report ingestion and route eligibility still require SecurityCheckedAt.
func validateStoredEntryHealth(desired Desired, health *EntryHealthReport) error {
	if err := validateEntryHealth(desired, health); err == nil {
		return nil
	}
	if health == nil {
		return nil
	}
	copy := (Observation{EntryHealth: health}).clone().EntryHealth
	for id, peer := range copy.Peers {
		s := &peer.Status
		if s.State == "healthy" && s.SecurityCheckedAt.IsZero() && s.ConsecutiveFailures == 0 && s.ConsecutiveSuccesses == 0 &&
			!s.AllowedUntil.After(s.StartedAt.Add(15*time.Second)) {
			// Temporary validation value only; never stored or returned as proof.
			s.SecurityCheckedAt = s.StartedAt
			copy.Peers[id] = peer
		}
	}
	return validateEntryHealth(desired, copy)
}

// Only the one matching landing is tested. A blocked peer must not invalidate
// other landings that share the entry process. Missing/expired/future evidence
// fails closed; configuration flags and process readiness are insufficient.
func entryPeerFresh(entry Node, target Node, now time.Time) bool {
	if entry.Desired.Entry == nil || entry.Desired.EntryNetwork == nil || entry.Receipt == nil || entry.Receipt.EntryHealth == nil || validateEntryHealth(entry.Desired, entry.Receipt.EntryHealth) != nil {
		return false
	}
	health := entry.Receipt.EntryHealth
	if health.SampledAt.After(now) {
		return false
	}
	if target.Desired.Landing == nil || health.Source == nil || health.Source.Address != target.RouteEntries[entry.ID].Address {
		return false
	}
	peer, found := health.Peers[target.ID]
	if !found || peer.Identity.Address != target.Desired.Landing.Address {
		return false
	}
	status := peer.Status
	return (status.State == "healthy" || status.State == "degraded") && !status.StartedAt.After(now) && !status.CheckedAt.After(now) && status.AllowedUntil.After(now)
}

func invalidateChangedEntryProofs(nodes map[string]Node, old, current Node, now time.Time) error {
	for key, target := range nodes {
		if _, found := target.RouteEntries[current.ID]; !found {
			continue
		}
		if runtimeFresh(old, now) != runtimeFresh(current, now) || entryPeerFresh(old, target, now) != entryPeerFresh(current, target, now) {
			check, found := target.Checks[current.ID]
			if !found {
				continue
			}
			attempt, err := newRouteAttempt()
			if err != nil {
				return err
			}
			// Preserve the complete authorized inventory and other entries'
			// results. A new challenge prevents replay of the old success or
			// an in-flight check started before this peer's readiness change.
			check.Request.AttemptID = attempt
			check.IssuedAt, check.ReceivedAt = now, time.Time{}
			check.Result = nil
			target.Checks = maps.Clone(target.Checks)
			target.Checks[current.ID] = check
			nodes[key] = target
		}
	}
	return nil
}

func entryRouteMatches(entry Node, probe RouteProbe) bool {
	if entry.Desired.EntryNetwork == nil {
		return false
	}
	for _, peer := range entry.Desired.EntryNetwork.Peers {
		if peer.EgressID == probe.LandingID {
			return peer.Target == probe.Target && peer.ExpectedExit == probe.ExpectedExit
		}
	}
	return false
}
