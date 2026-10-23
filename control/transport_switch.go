package control

import (
	"errors"
	"maps"
	"math"
	"reflect"
	"time"

	glivela "github.com/petauron/glivela"
)

// TransportCheckpoint is a compare-and-swap checkpoint, not a new ledger.
// Operators must fence ingress and submit the final counters through the
// existing node-authenticated exchange before requesting this operation.
type TransportCheckpoint struct {
	Revision     uint64        `json:"revision"`
	ConfigSHA256 string        `json:"configSha256"`
	Traffic      *EntryTraffic `json:"traffic,omitempty"`
}

type TransportSwitch struct {
	Recover   bool                           `json:"recover,omitempty"`
	LandingID string                         `json:"landingId"`
	Transport glivela.PrivateTransport       `json:"transport"`
	Expected  map[string]TransportCheckpoint `json:"expected"`
}

// SwitchPrivateTransport updates one landing and its retained entry policies
// in one durable controller transaction. Remote activation is deliberately not
// described as atomic: operators keep ingress fenced until route acceptance.
// A rollback is another monotonic transaction, never a database restore.
func (s *Store) SwitchPrivateTransport(request TransportSwitch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: private transport switch prerequisites not verified")
	if !glivela.ValidIdentifier(request.LandingID) || request.Transport.Validate() != nil || len(request.Expected) == 0 || len(request.Expected) > 65 || s.business != nil {
		return invalid
	}
	next := s.copy()
	landingKey := ""
	for key, n := range next {
		if n.ID == request.LandingID && n.Desired.Landing != nil {
			landingKey = key
		}
	}
	if landingKey == "" {
		return invalid
	}
	landingNode := next[landingKey]
	landingNode.Checks = maps.Clone(landingNode.Checks)
	if landingNode.Desired.Landing.Transport == request.Transport {
		return invalid
	}
	if request.Recover && (landingNode.TransportPrevious == nil || landingNode.TransportPrevious.Landing == nil || landingNode.TransportPrevious.Landing.Transport != request.Transport) {
		return invalid
	}
	changed := map[string]bool{landingNode.ID: true}
	now := time.Now().UTC()
	check := func(n Node, entry bool) bool {
		expected, ok := request.Expected[n.ID]
		if !ok || expected.Revision != n.Desired.Revision || expected.ConfigSHA256 != n.Desired.ConfigSHA256 || n.Desired.Revision == math.MaxUint64 {
			return false
		}
		if !entry {
			return expected.Traffic == nil
		}
		if n.TransportTail == nil || validateTransportTail(n, n.TransportTail) != nil || !reflect.DeepEqual(expected.Traffic, n.TransportTail.Traffic) {
			return false
		}
		if !request.Recover && n.TransportTail.validate(n.Desired) != nil {
			return false
		}
		if n.EntryQuota != nil && !reflect.DeepEqual(n.EntryQuota.Raw, expected.Traffic) {
			return false
		}
		return !expected.Traffic.SampledAt.After(now) && now.Sub(expected.Traffic.SampledAt) <= time.Minute
	}
	if !check(landingNode, false) {
		return invalid
	}
	for key, n := range next {
		if n.Desired.Entry == nil {
			continue
		}
		current := n.Desired.clone()
		found := false
		for i, peer := range current.Entry.Peers {
			if peer.EgressID != request.LandingID {
				continue
			}
			if peer.Transport != landingNode.Desired.Landing.Transport || peer.Address != landingNode.Desired.Landing.Address {
				return invalid
			}
			current.Entry.Peers[i].Transport = request.Transport
			found = true
		}
		if !found {
			continue
		}
		if request.Recover {
			if n.TransportPrevious == nil || n.TransportPrevious.Entry == nil {
				return invalid
			}
			previous := n.TransportPrevious.clone()
			previous.Entry.Revision = current.Entry.Revision
			if !reflect.DeepEqual(previous.Entry, current.Entry) || !reflect.DeepEqual(previous.EntryNetwork, current.EntryNetwork) {
				return invalid
			}
		}
		if !check(n, true) {
			return invalid
		}
		current.Entry.Revision++
		if n.EntryQuota != nil {
			q := n.EntryQuota.clone()
			if q.TransportOrigin == nil {
				origin := q.Base.clone()
				q.TransportOrigin = &origin
			}
			for i, peer := range q.Base.Entry.Peers {
				if peer.EgressID == request.LandingID {
					q.Base.Entry.Peers[i].Transport = request.Transport
				}
			}
			q.Base.Entry.Revision = current.Entry.Revision
			base, err := NewEntryDesired(*q.Base.Entry, *q.Base.EntryNetwork)
			if err != nil {
				return invalid
			}
			q.Base = base
			current.Entry = q.plan(current.Entry.Revision)
			n.EntryQuota = q
		}
		desired, err := NewEntryDesired(*current.Entry, *current.EntryNetwork)
		if err != nil {
			return invalid
		}
		previous := n.Desired.clone()
		n.TransportPrevious = &previous
		n.Desired = desired
		n.TransportTail = nil
		if n.EntryQuota != nil && n.EntryQuota.validateDesired(desired) != nil {
			return invalid
		}
		n.Receipt = nil
		n.ReportedAt = time.Time{}
		n.EntryHealthBarrierAt = now
		next[key] = n
		changed[n.ID] = true
	}
	// Every active source must be represented by an enrolled entry checkpoint.
	// Explicitly deferred sources retain their original identity and history;
	// they are not counted as tested and need migration before resuming.
	deferred := s.deferredEntries(landingNode, now)
	for id := range landingNode.RouteEntries {
		if !changed[id] && !deferred[id] {
			return invalid
		}
	}
	if len(changed) != len(request.Expected) {
		return invalid
	}
	for id := range request.Expected {
		if !changed[id] {
			return invalid
		}
	}
	plan := *landingNode.Desired.clone().Landing
	plan.Revision++
	plan.Transport = request.Transport
	desired, err := NewDesired(plan)
	if err != nil {
		return invalid
	}
	previous := landingNode.Desired.clone()
	landingNode.TransportPrevious = &previous
	landingNode.Desired = desired
	landingNode.Receipt = nil
	landingNode.ReportedAt = time.Time{}
	// Retain the authorized inventory and snapshot identity, but never carry
	// forward a successful proof obtained with the previous protocol/key.
	for id, check := range landingNode.Checks {
		attempt, err := newRouteAttempt()
		if err != nil {
			return err
		}
		check.Request.AttemptID = attempt
		check.Request.Revision = desired.Revision
		check.Request.ConfigSHA256 = desired.ConfigSHA256
		check.Request.Transport = request.Transport
		check.IssuedAt = now
		check.Result = nil
		check.ReceivedAt = time.Time{}
		landingNode.Checks[id] = check
	}
	next[landingKey] = landingNode
	return s.commit(next)
}
