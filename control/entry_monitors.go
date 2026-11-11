package control

import (
	"context"
	"errors"
	"github.com/petauron/glivela/landing"
	"log"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type entryMonitorGroup struct {
	desired  Desired
	statuses map[string]landing.MonitorStatus
}
type entryMonitors struct {
	mu    sync.Mutex
	group *entryMonitorGroup
}

func (m *entryMonitors) close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.group = nil
	return nil
}
func (m *entryMonitors) verify(d Desired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.group == nil || m.group.desired.Revision != d.Revision || m.group.desired.ConfigSHA256 != d.ConfigSHA256 || !reflect.DeepEqual(m.group.desired.EntryNetwork, d.EntryNetwork) {
		return errors.New("control: entry startup acceptance unavailable")
	}
	return nil
}
func (d *EntryDriver) PeerStatus() map[string]landing.MonitorStatus {
	d.monitors.mu.Lock()
	defer d.monitors.mu.Unlock()
	out := map[string]landing.MonitorStatus{}
	if d.monitors.group != nil {
		for k, v := range d.monitors.group.statuses {
			out[k] = v
		}
	}
	return out
}
func (d *EntryDriver) EntryHealth(desired Desired) *EntryHealthReport {
	return d.monitors.health(desired)
}
func (m *entryMonitors) health(d Desired) *EntryHealthReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.group
	if g == nil || g.desired.Revision != d.Revision || g.desired.ConfigSHA256 != d.ConfigSHA256 {
		return nil
	}
	h := &EntryHealthReport{SampledAt: time.Now().UTC(), Peers: map[string]EntryPeerObservation{}}
	if d.EntryNetwork.Source != nil {
		source := *d.EntryNetwork.Source
		h.Source = &source
	}
	for _, p := range d.EntryNetwork.Peers {
		h.Peers[p.EgressID] = EntryPeerObservation{Identity: p.Identity, Status: g.statuses[p.EgressID]}
	}
	return h
}
func (d *EntryDriver) startMonitors(ctx context.Context, desired Desired, gates []*landing.TrafficGate) error {
	return d.monitors.start(ctx, desired, gates, d.Container.ApplicationID, d.readyProcess, d.links)
}
func (m *entryMonitors) start(ctx context.Context, desired Desired, gates []*landing.TrafficGate, entryID string, ready func(context.Context, Desired) error, links func() *landing.LinkChecker, coreProbe ...func(context.Context, RouteProbe) (RouteProbeResult, error)) error {
	if len(gates) != len(desired.EntryNetwork.Peers) {
		return errors.New("control: startup peer inventory differs")
	}
	g := &entryMonitorGroup{desired: desired.clone(), statuses: map[string]landing.MonitorStatus{}}
	verifySource := func() error {
		if desired.EntryNetwork.Source == nil {
			return nil
		}
		checker := landing.NewLinkChecker()
		if links != nil {
			checker.Close()
			checker = links()
		}
		defer checker.Close()
		return verifyStartupSelfIdentity(ctx, *desired.EntryNetwork.Source, checker)
	}
	if err := verifySource(); err != nil {
		return err
	}
	// Landing reachability has its own bounded startup budget. Exhausting it
	// leaves the remaining peers closed; it does not invalidate direct readiness.
	peerDeadline := time.Now().Add(20 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Add(-3*time.Second).Before(peerDeadline) {
		// Retain time to confirm closed fences and the entry process after
		// landing probes time out. The caller's startup deadline is unchanged.
		peerDeadline = deadline.Add(-3 * time.Second)
	}
	peerContext, cancel := context.WithDeadline(ctx, peerDeadline)
	defer cancel()
	// Each peer is checked only during activation. Runtime heartbeats return the
	// accepted proof; elapsed time and third-party availability cannot revoke it.
	for index, peer := range desired.EntryNetwork.Peers {
		entryFailed := false
		checker := landing.NewLinkChecker()
		if links != nil {
			checker.Close()
			checker = links()
		}
		monitor := landing.Monitor{Gate: gates[index], Links: checker, TCPOnly: true, ExpectedExit: peer.ExpectedExit,
			CheckBusiness: func(check context.Context, identity landing.PeerIdentity, revision uint64) (landing.BusinessResult, error) {
				result := landing.BusinessResult{Peer: identity, Revision: revision, StartedAt: time.Now()}
				before, err := checker.SelfIdentity(check, desired.EntryNetwork.Source.Address)
				if err != nil || before != *desired.EntryNetwork.Source {
					entryFailed = check.Err() == nil
					return result, errors.New("control: startup entry identity changed")
				}
				if err = ready(check, desired); err != nil {
					entryFailed = check.Err() == nil
					return result, err
				}
				probe := RouteProbe{AttemptID: "entry-startup", SnapshotID: desired.ConfigSHA256, EntryID: entryID, LandingID: peer.EgressID, Revision: revision, ConfigSHA256: desired.ConfigSHA256, SOCKSAddress: net.JoinHostPort(identity.Address, "1080"), Target: peer.Target, ExpectedExit: peer.ExpectedExit}
				for _, route := range desired.Entry.Peers {
					if route.EgressID == peer.EgressID {
						probe.Transport = route.Transport
						probe.SOCKSAddress = net.JoinHostPort(route.Transport.Endpoint(route.Address), strconv.Itoa(route.Port))
					}
				}
				checkRoute := CheckRoute
				if len(coreProbe) == 1 {
					checkRoute = coreProbe[0]
				}
				observed, err := checkRoute(check, probe)
				if err != nil {
					return result, err
				}
				after, err := checker.SelfIdentity(check, desired.EntryNetwork.Source.Address)
				if err != nil || after != before {
					entryFailed = check.Err() == nil
					return result, errors.New("control: startup entry identity changed during probe")
				}
				if err = ready(check, desired); err != nil {
					entryFailed = check.Err() == nil
					return result, err
				}
				result.TCP, result.ExitIP, result.CheckedAt = observed.Passed, observed.ObservedExit, time.Now()
				return result, nil
			}, Report: func(status landing.MonitorStatus) { g.statuses[peer.EgressID] = status }}
		if err := monitor.Run(peerContext); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if entryFailed {
				return err
			}
			// Continue only after reading back this exact owned, closed gate.
			// A firewall/ownership failure still rejects the whole activation.
			if blocked := gates[index].Block(ctx); blocked != nil {
				return errors.Join(err, blocked)
			}
			log.Printf("Glivela startup check blocked enrolled peer %s; direct entry remains independent: %v", peer.EgressID, err)
		}
	}
	if err := ready(ctx, desired); err != nil {
		return err
	}
	if err := verifySource(); err != nil {
		return err
	}
	m.mu.Lock()
	m.group = g
	m.mu.Unlock()
	return nil
}

func sameEntryTransport(a, b *EntryNetwork) bool {
	if a == nil || b == nil || !reflect.DeepEqual(a.Source, b.Source) || len(a.Peers) != len(b.Peers) {
		return false
	}
	peers := make(map[string]landing.PeerIdentity, len(a.Peers))
	for _, peer := range a.Peers {
		peers[peer.EgressID] = peer.Identity
	}
	for _, peer := range b.Peers {
		if peers[peer.EgressID] != peer.Identity {
			return false
		}
	}
	return true
}
