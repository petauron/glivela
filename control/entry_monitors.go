package control

import (
	"context"
	"errors"
	"log"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/petauron/glivela/landing"
)

type entryMonitorGroup struct {
	cancel   context.CancelFunc
	done     chan struct{}
	stopping bool
	desired  Desired
	statuses map[string]landing.MonitorStatus
}
type entryMonitors struct {
	verifyPublicPeer PublicPeerVerifier
	mu               sync.Mutex
	group            *entryMonitorGroup
}

func (m *entryMonitors) close(ctx context.Context) error {
	m.mu.Lock()
	g := m.group
	if g != nil {
		g.stopping = true
		if g.cancel != nil {
			g.cancel()
		}
	}
	m.mu.Unlock()
	if g == nil {
		return nil
	}
	if g.done != nil {
		select {
		case <-ctx.Done():
			return errors.New("control: entry startup retry still stopping")
		case <-g.done:
		}
	}
	m.mu.Lock()
	if m.group == g {
		m.group = nil
	}
	m.mu.Unlock()
	return nil
}
func (m *entryMonitors) verify(d Desired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.group == nil || m.group.stopping || m.group.desired.Revision != d.Revision || m.group.desired.ConfigSHA256 != d.ConfigSHA256 || !reflect.DeepEqual(m.group.desired.EntryNetwork, d.EntryNetwork) {
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
	if g == nil || g.stopping || g.desired.Revision != d.Revision || g.desired.ConfigSHA256 != d.ConfigSHA256 || !reflect.DeepEqual(g.desired.EntryNetwork, d.EntryNetwork) {
		return nil
	}
	h := &EntryHealthReport{SampledAt: time.Now().UTC(), Peers: map[string]EntryPeerObservation{}}
	if d.EntryNetwork.Source != nil {
		source := *d.EntryNetwork.Source
		h.Source = &source
	}
	for _, p := range d.EntryNetwork.Peers {
		h.Peers[p.PeerKey()] = EntryPeerObservation{Identity: p.Identity, Status: g.statuses[p.PeerKey()]}
	}
	return h
}
func (d *EntryDriver) startMonitors(ctx context.Context, desired Desired, gates []*landing.TrafficGate) error {
	before, err := d.inspect(ctx, desired)
	if err != nil {
		return err
	}
	ready := func(check context.Context, want Desired) error {
		if err := d.readyProcess(check, want); err != nil {
			return err
		}
		after, err := d.inspect(check, want)
		if err != nil || after.State != before.State {
			return errors.New("control: entry changed during startup recovery")
		}
		return nil
	}
	return d.monitors.start(ctx, desired, gates, d.Container.ApplicationID, ready, d.links)
}
func (m *entryMonitors) start(ctx context.Context, desired Desired, gates []*landing.TrafficGate, entryID string, ready func(context.Context, Desired) error, links func() *landing.LinkChecker, coreProbe ...func(context.Context, RouteProbe) (RouteProbeResult, error)) error {
	if len(gates) != len(desired.EntryNetwork.Peers) {
		return errors.New("control: startup peer inventory differs")
	}
	if err := m.close(ctx); err != nil {
		return err
	}
	g := &entryMonitorGroup{desired: desired.clone(), statuses: map[string]landing.MonitorStatus{}}
	desired = g.desired
	verifySource := func(check context.Context) error {
		if desired.EntryNetwork.Source == nil {
			return nil
		}
		checker := landing.NewLinkChecker()
		if links != nil {
			checker.Close()
			checker = links()
		}
		defer checker.Close()
		return verifyStartupSelfIdentity(check, *desired.EntryNetwork.Source, checker)
	}
	if err := verifySource(ctx); err != nil {
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
	// Each attempt uses fresh evidence and a fresh checker. Only peers whose
	// startup acceptance failed are retried; accepted peers stay untouched.
	checkPeer := func(check, fence context.Context, index int) (bool, error) {
		peer := desired.EntryNetwork.Peers[index]
		entryFailed := false
		checker := landing.NewLinkChecker()
		if links != nil {
			checker.Close()
			checker = links()
		}
		monitor := landing.Monitor{Gate: gates[index], Links: checker, TCPOnly: true, ExpectedExit: peer.ExpectedExit,
			CheckPublicIdentity: func(check context.Context, identity landing.PeerIdentity) landing.LinkResult {
				if m.verifyPublicPeer == nil || identity != peer.Identity {
					return landing.LinkResult{State: "unknown", Reason: "peer_identity_unavailable"}
				}
				return m.verifyPublicPeer(check, desired, peer)
			},
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
					if route.PeerKey() == peer.PeerKey() {
						probe.Transport = route.Transport
						probe.Relay = route.Relay
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
			}, Report: func(status landing.MonitorStatus) {
				m.mu.Lock()
				g.statuses[peer.PeerKey()] = status
				m.mu.Unlock()
			}}
		if err := monitor.Run(check); err != nil {
			if fence.Err() != nil {
				return false, fence.Err()
			}
			if entryFailed {
				return false, err
			}
			// Continue only after reading back this exact owned, closed gate.
			// A firewall/ownership failure still rejects the whole activation.
			if blocked := gates[index].Block(fence); blocked != nil {
				return false, errors.Join(err, blocked)
			}
			log.Printf("Glivela startup check blocked enrolled peer %s; direct entry remains independent: %v", peer.EgressID, err)
			return true, err
		}
		return false, nil
	}
	var pending []int
	for index := range desired.EntryNetwork.Peers {
		retry, err := checkPeer(peerContext, ctx, index)
		if err != nil {
			if !retry {
				return err
			}
			pending = append(pending, index)
		}
	}
	if err := ready(ctx, desired); err != nil {
		return err
	}
	if err := verifySource(ctx); err != nil {
		return err
	}
	// The retry lifetime belongs to this applied group, not to the activation
	// request. close cancels and joins it before configuration or gates change.
	retryContext, stop := context.WithCancel(context.Background())
	g.cancel, g.done = stop, make(chan struct{})
	m.mu.Lock()
	m.group = g
	m.mu.Unlock()
	if len(pending) == 0 {
		stop()
		close(g.done)
		return nil
	}
	go func() {
		defer close(g.done)
		defer stop()
		delay := 5 * time.Second
		for len(pending) > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-retryContext.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			remaining := pending[:0]
			for _, index := range pending {
				attempt, cancelAttempt := context.WithTimeout(retryContext, 20*time.Second)
				err := verifySource(attempt)
				if err == nil {
					err = ready(attempt, desired)
				}
				if err == nil {
					// A fresh fence context retains cleanup time when the bounded
					// business check expires, without outliving group cancellation.
					fence, cancelFence := context.WithTimeout(retryContext, 25*time.Second)
					retry, checkErr := checkPeer(attempt, fence, index)
					cancelFence()
					err = checkErr
					if err != nil && !retry {
						cancelAttempt()
						return
					}
				}
				cancelAttempt()
				if retryContext.Err() != nil {
					return
				}
				if err != nil {
					remaining = append(remaining, index)
				}
			}
			pending = remaining
			if delay < time.Minute {
				delay = min(2*delay, time.Minute)
			}
		}
	}()
	return nil
}

func sameEntryTransport(a, b *EntryNetwork) bool {
	if a == nil || b == nil || !reflect.DeepEqual(a.Source, b.Source) || len(a.Peers) != len(b.Peers) {
		return false
	}
	peers := make(map[string]EntryPeer, len(a.Peers))
	for _, peer := range a.Peers {
		peers[peer.PeerKey()] = peer
	}
	for _, peer := range b.Peers {
		previous, ok := peers[peer.PeerKey()]
		if !ok || previous.Identity != peer.Identity || !reflect.DeepEqual(previous.RelayIdentity, peer.RelayIdentity) {
			return false
		}
	}
	return true
}
