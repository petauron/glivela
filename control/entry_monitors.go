package control

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/petauron/glivela/landing"
)

type entryMonitorGroup struct {
	cancel   context.CancelFunc
	done     chan struct{}
	desired  Desired
	active   map[string]bool
	statuses map[string]landing.MonitorStatus
	stopping bool
}

type entryMonitors struct {
	mu    sync.Mutex
	group *entryMonitorGroup
}

func (m *entryMonitors) close(ctx context.Context) error {
	m.mu.Lock()
	g := m.group
	if g != nil {
		g.stopping = true
		g.cancel()
	}
	m.mu.Unlock()
	if g == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return errors.New("control: entry monitors still stopping")
	case <-g.done:
	}
	m.mu.Lock()
	if m.group == g {
		m.group = nil
	}
	m.mu.Unlock()
	return nil
}

func (m *entryMonitors) verify(desired Desired) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(desired.EntryNetwork.Peers) == 0 {
		if m.group != nil {
			return errors.New("control: unexpected routed entry monitors")
		}
		return nil
	}
	g := m.group
	if g == nil || g.stopping || g.desired.Revision != desired.Revision || g.desired.ConfigSHA256 != desired.ConfigSHA256 || !reflect.DeepEqual(g.desired.EntryNetwork, desired.EntryNetwork) {
		return errors.New("control: entry monitor revision differs")
	}
	select {
	case <-g.done:
		return errors.New("control: entry monitors stopped")
	default:
	}
	for _, peer := range desired.EntryNetwork.Peers {
		if !g.active[peer.EgressID] {
			return errors.New("control: entry peer monitor unavailable")
		}
	}
	return nil
}

// PeerStatus is current Glivela-local diagnostic data, not a substitute for
// authenticated controller-side route acceptance. A blocked peer never causes
// the shared container to restart or changes another peer's gate.
func (d *EntryDriver) PeerStatus() map[string]landing.MonitorStatus {
	d.monitors.mu.Lock()
	defer d.monitors.mu.Unlock()
	result := map[string]landing.MonitorStatus{}
	if g := d.monitors.group; g != nil {
		for id, status := range g.statuses {
			result[id] = status
		}
	}
	return result
}

func (d *EntryDriver) EntryHealth(desired Desired) *EntryHealthReport {
	return d.monitors.health(desired)
}

func (m *entryMonitors) health(desired Desired) *EntryHealthReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.group
	if desired.Entry == nil || desired.EntryNetwork == nil || g == nil || g.stopping || g.desired.Revision != desired.Revision || g.desired.ConfigSHA256 != desired.ConfigSHA256 || !reflect.DeepEqual(g.desired.EntryNetwork, desired.EntryNetwork) {
		return nil
	}
	select {
	case <-g.done:
		return nil
	default:
	}
	health := &EntryHealthReport{SampledAt: time.Now().UTC(), Peers: map[string]EntryPeerObservation{}}
	if g.desired.EntryNetwork.Source != nil {
		source := *g.desired.EntryNetwork.Source
		health.Source = &source
	}
	for _, peer := range g.desired.EntryNetwork.Peers {
		status, found := g.statuses[peer.EgressID]
		if !found || !g.active[peer.EgressID] {
			return nil
		}
		health.Peers[peer.EgressID] = EntryPeerObservation{Identity: peer.Identity, Status: status}
	}
	return health
}

func (d *EntryDriver) startMonitors(desired Desired, gates []*landing.TrafficGate) error {
	return d.monitors.start(desired, gates, d.Container.ApplicationID, d.readyProcess, d.stopOwned, d.links)
}

func (m *entryMonitors) start(desired Desired, gates []*landing.TrafficGate, entryID string, ready, stop func(context.Context, Desired) error, links func() *landing.LinkChecker) error {
	if len(desired.EntryNetwork.Peers) == 0 {
		return nil
	}
	if len(gates) != len(desired.EntryNetwork.Peers) {
		return errors.New("control: entry monitor inventory differs")
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &entryMonitorGroup{cancel: cancel, done: make(chan struct{}), desired: desired.clone(), active: map[string]bool{}, statuses: map[string]landing.MonitorStatus{}}
	m.mu.Lock()
	if m.group != nil {
		m.mu.Unlock()
		cancel()
		return errors.New("control: previous entry monitors still owned")
	}
	for _, peer := range desired.EntryNetwork.Peers {
		g.active[peer.EgressID] = true
		g.statuses[peer.EgressID] = landing.MonitorStatus{Revision: desired.Revision, State: "blocked", Reason: "monitor-starting"}
	}
	m.group = g
	m.mu.Unlock()
	var workers sync.WaitGroup
	var quarantine sync.Once
	for index, peer := range desired.EntryNetwork.Peers {
		checker := landing.NewLinkChecker()
		if links != nil {
			checker.Close()
			checker = links()
		}
		monitor := landing.Monitor{Gate: gates[index], Links: checker, TCPOnly: true, ExpectedExit: peer.ExpectedExit,
			CheckBusiness: func(check context.Context, identity landing.PeerIdentity, revision uint64) (landing.BusinessResult, error) {
				started := time.Now()
				result := landing.BusinessResult{Peer: identity, Revision: revision, StartedAt: started}
				before, err := checker.SelfIdentity(check, desired.EntryNetwork.Source.Address)
				if err != nil || before != *desired.EntryNetwork.Source {
					return result, errors.New("control: entry private identity changed")
				}
				if err := ready(check, desired); err != nil {
					return result, err
				}
				probe := RouteProbe{AttemptID: "entry-monitor", SnapshotID: desired.ConfigSHA256, EntryID: entryID, LandingID: peer.EgressID, Revision: revision, ConfigSHA256: desired.ConfigSHA256, SOCKSAddress: net.JoinHostPort(identity.Address, "1080"), Target: peer.Target, ExpectedExit: peer.ExpectedExit}
				observed, err := CheckRoute(check, probe)
				if err != nil {
					return result, err
				}
				after, err := checker.SelfIdentity(check, desired.EntryNetwork.Source.Address)
				if err != nil || after != before {
					return result, errors.New("control: entry private identity changed during probe")
				}
				if err := ready(check, desired); err != nil {
					return result, err
				}
				result.TCP, result.ExitIP, result.CheckedAt = observed.Passed, observed.ObservedExit, time.Now()
				return result, nil
			}, Report: func(status landing.MonitorStatus) {
				m.mu.Lock()
				if m.group == g {
					g.statuses[peer.EgressID] = status
				}
				m.mu.Unlock()
			},
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := monitor.Run(ctx)
			m.mu.Lock()
			g.active[peer.EgressID] = false
			if err != nil && ctx.Err() == nil {
				g.stopping = true
			}
			g.statuses[peer.EgressID] = landing.MonitorStatus{Revision: desired.Revision, State: "blocked", Reason: "monitor-stopped", CheckedAt: time.Now().UTC()}
			m.mu.Unlock()
			if err != nil && ctx.Err() == nil {
				// Ordinary probe failures stay in Monitor.Run and close only
				// their peer. A fatal loss of gate ownership is different: the
				// security barrier is unknown. Stop the exact owned worker,
				// without an automatic restart or deletion of foreign policy.
				quarantine.Do(func() {
					fence, done := context.WithTimeout(context.Background(), 15*time.Second)
					defer done()
					for _, gate := range gates {
						_ = gate.Block(fence)
					}
					_ = stop(fence, desired)
				})
			}
		}()
	}
	go func() { workers.Wait(); close(g.done) }()
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
