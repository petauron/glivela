package control

import (
	"errors"
	"maps"
	"math"
	"reflect"
	"time"
)

// ProbeUpdate reuses the existing drained-worker checkpoint. It is not hot
// re-enrollment: live connections finish before the node seals its counters.
type ProbeUpdate struct {
	EntryID  string              `json:"entryId"`
	Expected TransportCheckpoint `json:"expected"`
	Targets  map[string]string   `json:"targets"`
}

func sameProbeNetworkIdentity(before, after *EntryNetwork) bool {
	if before == nil || after == nil || len(before.Peers) != len(after.Peers) {
		return false
	}
	old := before.clone()
	for i := range old.Peers {
		old.Peers[i].Target = after.Peers[i].Target
	}
	return reflect.DeepEqual(old, *after)
}

func probeOnlyEntryChange(before, after Desired) bool {
	if before.Validate() != nil || after.Validate() != nil || before.Entry == nil || after.Entry == nil || before.EntryNetwork == nil || after.EntryNetwork == nil {
		return false
	}
	old := before.clone()
	old.Entry.Revision = after.Entry.Revision
	if !reflect.DeepEqual(old.Entry, after.Entry) || len(old.EntryNetwork.Peers) != len(after.EntryNetwork.Peers) {
		return false
	}
	changed := false
	for i := range old.EntryNetwork.Peers {
		changed = changed || old.EntryNetwork.Peers[i].Target != after.EntryNetwork.Peers[i].Target
		old.EntryNetwork.Peers[i].Target = after.EntryNetwork.Peers[i].Target
	}
	return changed && reflect.DeepEqual(old.EntryNetwork, after.EntryNetwork)
}

// UpdateProbeTargets changes only named HTTPS probe targets. A fresh,
// node-authenticated tail is mandatory even though Xray configuration is
// unchanged: applying a new monitor revision replaces its firewall gates.
func (s *Store) UpdateProbeTargets(request ProbeUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: drained probe update prerequisites not verified")
	if s.business != nil || len(request.Targets) == 0 || len(request.Targets) > 64 {
		return invalid
	}
	key := ""
	for certificate, n := range s.nodes {
		if n.ID == request.EntryID && n.Desired.Entry != nil {
			key = certificate
		}
	}
	n, ok := s.nodes[key]
	if !ok || n.EntryQuota == nil || n.Desired.EntryNetwork == nil || n.Desired.Revision == math.MaxUint64 ||
		request.Expected.Revision != n.Desired.Revision || request.Expected.ConfigSHA256 != n.Desired.ConfigSHA256 ||
		n.TransportTail == nil || validateTransportTail(n, n.TransportTail) != nil ||
		!reflect.DeepEqual(request.Expected.Traffic, n.TransportTail.Traffic) || !reflect.DeepEqual(n.EntryQuota.Raw, n.TransportTail.Traffic) {
		return invalid
	}
	now := time.Now().UTC()
	if request.Expected.Traffic.SampledAt.After(now) || now.Sub(request.Expected.Traffic.SampledAt) > time.Minute {
		return invalid
	}
	current := n.Desired.clone()
	changed := 0
	for i, peer := range current.EntryNetwork.Peers {
		if target, found := request.Targets[peer.EgressID]; found {
			if !validRouteTarget(target) || target == peer.Target {
				return invalid
			}
			current.EntryNetwork.Peers[i].Target = target
			changed++
		}
	}
	if changed != len(request.Targets) {
		return invalid
	}
	current.Entry.Revision++
	desired, err := NewEntryDesired(*current.Entry, *current.EntryNetwork)
	if err != nil || !probeOnlyEntryChange(n.Desired, desired) {
		return invalid
	}
	previous := n.Desired.clone()
	if n.TransportTail.validate(n.Desired) != nil {
		// Failed activation may still be running the retained generation.
		// Only restoring that exact probe policy is allowed in this case.
		if n.TransportPrevious == nil || !probeOnlyEntryChange(*n.TransportPrevious, n.Desired) || !reflect.DeepEqual(n.TransportPrevious.EntryNetwork, desired.EntryNetwork) {
			return invalid
		}
		previous = n.TransportPrevious.clone()
	}
	q := n.EntryQuota.clone()
	if q.TransportOrigin == nil {
		origin := q.Base.clone()
		q.TransportOrigin = &origin
	}
	base := q.Base.clone()
	for i := range base.EntryNetwork.Peers {
		if target, found := request.Targets[base.EntryNetwork.Peers[i].EgressID]; found {
			base.EntryNetwork.Peers[i].Target = target
		}
	}
	base.Entry.Revision = desired.Revision
	q.Base, err = NewEntryDesired(*base.Entry, *base.EntryNetwork)
	if err != nil || q.validate() != nil || q.validateDesired(desired) != nil {
		return invalid
	}
	n.EntryQuota, n.Desired, n.TransportPrevious = q, desired, &previous
	n.TransportTail, n.Receipt = nil, nil
	n.ReportedAt, n.EntryHealthBarrierAt = time.Time{}, now
	next := s.copy()
	next[key] = n
	// Keep each landing's complete inventory and snapshot identity. Only this
	// entry's changed target loses its old proof; unrelated checks stay intact.
	for certificate, node := range next {
		check, found := node.Checks[n.ID]
		target, changed := request.Targets[node.ID]
		if !found || !changed {
			continue
		}
		attempt, err := newRouteAttempt()
		if err != nil {
			return err
		}
		check.Request.Target, check.Request.AttemptID = target, attempt
		check.Result, check.ReceivedAt, check.IssuedAt = nil, time.Time{}, now
		node.Checks = maps.Clone(node.Checks)
		node.Checks[n.ID] = check
		next[certificate] = node
	}
	return s.commit(next)
}
