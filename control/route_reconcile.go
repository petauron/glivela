package control

import (
	"maps"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/petauron/glivela/landing"
)

// Reuse the existing bounded route protocol. Only complete already-enrolled
// source inventories and their exact entry-owned probe targets are eligible.
// There is no platform task, guessed peer, arbitrary target or success override.
func reconcileOwnedRouteChecks(nodes map[string]Node, business *businessState, now time.Time, availability ...map[string]Availability) error {
	pauses := map[string]Availability{}
	if len(availability) == 1 {
		pauses = availability[0]
	}
	if business != nil && business.faulted {
		return nil
	}
	for certificate, node := range nodes {
		if node.Desired.Landing == nil || !runtimeFresh(node, now) || len(node.RouteEntries) == 0 {
			continue
		}
		snapshot := ""
		if business != nil && business.material.Ownership != nil {
			snapshot = business.snapshotID
		} else {
			for _, previous := range node.Checks {
				if snapshot != "" && snapshot != previous.Request.SnapshotID {
					snapshot = ""
					break
				}
				snapshot = previous.Request.SnapshotID
			}
		}
		if snapshot == "" {
			continue
		}
		checks := make(map[string]RouteCheck, len(node.RouteEntries))
		complete := true
		for id, authorized := range node.RouteEntries {
			pause, paused := pauses[id]
			if paused && (pause.ResumeAt.IsZero() || now.Before(pause.ResumeAt)) {
				continue
			}
			entry, enrolled := nodes[authorized.CertificateID]
			if !enrolled || entry.ID != id || entry.Desired.EntryNetwork == nil || entry.Desired.EntryNetwork.Source == nil || entry.Desired.EntryNetwork.Source.Address != authorized.Address {
				complete = false
				break
			}
			var peer *EntryPeer
			for i := range entry.Desired.EntryNetwork.Peers {
				candidate := &entry.Desired.EntryNetwork.Peers[i]
				if candidate.EgressID == node.ID && candidate.Identity.Address == node.Desired.Landing.Address {
					peer = candidate
					break
				}
			}
			if peer == nil {
				complete = false
				break
			}
			request := RouteProbe{SnapshotID: snapshot, EntryID: id, LandingID: node.ID, Revision: node.Desired.Revision, ConfigSHA256: node.Desired.ConfigSHA256, SOCKSAddress: net.JoinHostPort(node.Desired.Landing.Transport.Endpoint(node.Desired.Landing.Address), strconv.Itoa(landing.SOCKSPort)), Target: peer.Target, ExpectedExit: peer.ExpectedExit}
			request.Transport = node.Desired.Landing.Transport
			old, exists := node.Checks[id]
			request.AttemptID = old.Request.AttemptID
			reuse := exists && old.CertificateID == authorized.CertificateID && reflect.DeepEqual(old.Request, request) && !old.IssuedAt.After(now)
			if paused {
				reuse = reuse && old.IssuedAt.After(pause.ResumeAt) && old.IssuedAt.After(pause.ChangedAt)
			}
			if reuse && old.Result != nil {
				lifetime := 4 * time.Minute
				if !old.Result.Passed {
					lifetime = time.Minute
				}
				reuse = !old.ReceivedAt.IsZero() && !old.ReceivedAt.After(now) && now.Sub(old.ReceivedAt) < lifetime
			} else if reuse {
				reuse = now.Sub(old.IssuedAt) < 4*time.Minute
			}
			if reuse {
				checks[id] = old
				continue
			}
			attempt, err := newRouteAttempt()
			if err != nil {
				return err
			}
			request.AttemptID = attempt
			if request.Validate() != nil {
				complete = false
				break
			}
			checks[id] = RouteCheck{CertificateID: authorized.CertificateID, Request: request, IssuedAt: now}
		}
		if !complete {
			continue
		} // Never turn a partial inventory into acceptance.
		if !reflect.DeepEqual(node.Checks, checks) {
			node.Checks = maps.Clone(checks)
			nodes[certificate] = node
		}
	}
	return nil
}
