package control

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// Diagnostics never change desired state, accounting or route acceptance.
// Only completed samples are retained as display history across restarts.
type LatencyProbe struct {
	AttemptID string `json:"attemptId"`
	EntryID   string `json:"entryId"`
	LandingID string `json:"landingId"`
	Address   string `json:"address"`
	Source    string `json:"source,omitempty"`
	Port      int    `json:"port"`
}

func (p LatencyProbe) Validate() error {
	a, err := netip.ParseAddr(p.Address)
	if !glivela.ValidIdentifier(p.AttemptID) || !glivela.ValidIdentifier(p.EntryID) || !glivela.ValidIdentifier(p.LandingID) || err != nil || a.String() != p.Address || a.Zone() != "" || !a.IsGlobalUnicast() || p.Port != landing.SOCKSPort && (p.Port < 24000 || p.Port > 24999) {
		return errors.New("control: invalid latency assignment")
	}
	if p.Source != "" && (!glivela.PublicTransportIPv6(p.Source) || !glivela.PublicTransportIPv6(p.Address) || p.Source == p.Address || p.Port == landing.SOCKSPort) {
		return errors.New("control: invalid IPv6 latency source")
	}
	return nil
}

type LatencyResult struct {
	AttemptID     string   `json:"attemptId"`
	LatencyMillis *float64 `json:"latencyMs,omitempty"`
	Samples       int      `json:"samples"`
}

// LatencySample is one completed diagnostic round, retained for display.
type LatencySample struct {
	CheckedAt     time.Time `json:"checkedAt"`
	LatencyMillis *float64  `json:"latencyMs,omitempty"`
	Samples       int       `json:"samples"`
}

type LatencyView struct {
	EntryID            string          `json:"entryId"`
	LandingID          string          `json:"landingId"`
	Port               int             `json:"port"`
	Address            string          `json:"address"`
	Source             string          `json:"source,omitempty"`
	State              string          `json:"state"`
	CheckedAt          *time.Time      `json:"checkedAt,omitempty"`
	LatencyMillis      *float64        `json:"latencyMs,omitempty"`
	Samples            int             `json:"samples"`
	History            []LatencySample `json:"history,omitempty"`
	HistoryUnavailable bool            `json:"historyUnavailable,omitempty"`
}
type latencyTarget struct {
	Certificate     string
	EntryRevision   uint64
	LandingRevision uint64
	EntryHash       string
	LandingHash     string
	Address         string
	Source          string
	EntryID         string
	LandingID       string
	Port            int
}
type latencyRecord struct {
	Target    latencyTarget
	Probe     LatencyProbe
	QueuedAt  time.Time
	IssuedAt  time.Time
	CheckedAt time.Time
	Result    *LatencyResult
	History   []LatencySample
}

func latencyKey(entry, landing string, port int) string {
	return entry + "/" + landing + "/" + strconv.Itoa(port)
}

func latencyPathKey(entry, landing string, port int, source, address string) string {
	key := latencyKey(entry, landing, port)
	if source != "" {
		key += "/" + source + "/" + address
	}
	return key
}

func latencyTargetKey(t latencyTarget) string {
	return latencyPathKey(t.EntryID, t.LandingID, t.Port, t.Source, t.Address)
}

// Only the current enrolled transport can supply a target. The administrator
// and node APIs accept neither arbitrary addresses nor caller-chosen ports.
func (s *Store) latencyTargetsLocked() map[string]latencyTarget {
	out := map[string]latencyTarget{}
	landings := map[string]Node{}
	for _, n := range s.nodes {
		if n.Desired.Landing != nil {
			landings[n.ID] = n
		}
	}
	for cert, entry := range s.nodes {
		if entry.Desired.Entry == nil {
			continue
		}
		for _, peer := range entry.Desired.Entry.Peers {
			node, ok := landings[peer.EgressID]
			if !ok || !node.Desired.Landing.HasServerListener() {
				continue
			}
			enrolled, ok := node.RouteEntries[entry.ID]
			if !ok || enrolled.CertificateID != cert || peer.Transport != node.Desired.Landing.Transport || peer.Address != node.Desired.Landing.Address {
				continue
			}
			target := latencyTarget{Certificate: cert, EntryRevision: entry.Desired.Revision, LandingRevision: node.Desired.Revision, EntryHash: entry.Desired.ConfigSHA256, LandingHash: node.Desired.ConfigSHA256, Address: peer.Transport.Endpoint(peer.Address), EntryID: entry.ID, LandingID: node.ID, Port: landing.SOCKSPort}
			out[latencyKey(entry.ID, node.ID, target.Port)] = target
		}
	}
	if s.business == nil || s.business.material.Ownership == nil || s.business.faulted {
		return out
	}
	material := s.business.material
	credentials, _, err := effectiveBusinessCredentials(material, time.Now())
	if err != nil {
		return out
	}
	// Client chains own their exact transport independently of server-forwarding
	// peers. A projected listener and source grant must exist before diagnostics.
	for _, original := range material.ClientChains {
		chain, err := material.EffectiveClientChain(original)
		if err != nil {
			continue
		}
		peer, entry, node, ok := chainSpeedPeer(s.nodes, material, chain, credentials)
		if !ok || entry.Desired.EntryNetwork == nil || !slices.Contains(entry.Desired.EntryNetwork.SpeedPeers, peer) {
			continue
		}
		target := latencyTarget{Certificate: entry.CertificateID, EntryRevision: entry.Desired.Revision, LandingRevision: node.Desired.Revision, EntryHash: entry.Desired.ConfigSHA256, LandingHash: node.Desired.ConfigSHA256, Address: peer.Address, EntryID: entry.ID, LandingID: node.ID, Port: chain.Port}
		if chain.Transport == "ipv6-ss2022" {
			target.Source = peer.Source
		}
		if (LatencyProbe{AttemptID: "latency", EntryID: target.EntryID, LandingID: target.LandingID, Address: target.Address, Source: target.Source, Port: target.Port}).Validate() == nil {
			out[latencyTargetKey(target)] = target
		}
	}
	return out
}

func (s *Store) pruneLatenciesLocked(targets map[string]latencyTarget) {
	for k, r := range s.latencies {
		if t, ok := targets[k]; !ok || t != r.Target {
			delete(s.latencies, k)
		}
	}
}
func (s *Store) latencyOnlineLocked(t latencyTarget, now time.Time) bool {
	entry, ok := s.nodes[t.Certificate]
	if !ok || !s.availableRuntime(entry, now) {
		return false
	}
	for _, n := range s.nodes {
		if n.ID == t.LandingID {
			return s.availableRuntime(n, now)
		}
	}
	return false
}
func (s *Store) RouteLatencies(refresh, force bool) ([]LatencyView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	targets := s.latencyTargetsLocked()
	s.pruneLatenciesLocked(targets)
	if s.latencies == nil {
		s.latencies = map[string]*latencyRecord{}
	}
	now := time.Now().UTC()
	views := make([]LatencyView, 0, len(targets))
	for k, t := range targets {
		r := s.latencies[k]
		history := s.recentLatencyHistoryLocked(k, t)
		if r != nil {
			history = r.History
		}
		online := s.latencyOnlineLocked(t, now)
		interval := time.Minute
		if force {
			interval = 10 * time.Second
		}
		// Do not replace an in-flight attempt on each browser poll. Multiple tabs
		// share the same bounded queue and completed sample.
		due := r == nil || r.Result != nil && now.Sub(r.QueuedAt) >= interval || r.Result == nil && now.Sub(r.QueuedAt) > 2*time.Minute
		if refresh && online && due {
			attempt, err := newRouteAttempt()
			if err != nil {
				return nil, err
			}
			p := LatencyProbe{AttemptID: attempt, EntryID: t.EntryID, LandingID: t.LandingID, Address: t.Address, Source: t.Source, Port: t.Port}
			if p.Validate() != nil {
				continue
			}
			r = &latencyRecord{Target: t, Probe: p, QueuedAt: now, History: history}
			s.latencies[k] = r
		}
		v := LatencyView{EntryID: t.EntryID, LandingID: t.LandingID, Port: t.Port, Address: t.Address, Source: t.Source, State: "unknown", History: append([]LatencySample(nil), history...), HistoryUnavailable: s.latencyHistoryFault}
		if len(history) > 0 {
			v.State = "stale"
		}
		if r != nil {
			v.State = "pending"
			if r.Result != nil {
				checked := r.CheckedAt
				v.CheckedAt = &checked
				v.Samples = r.Result.Samples
				v.LatencyMillis = r.Result.LatencyMillis
				v.State = "ready"
				if v.Samples == 0 {
					v.State = "unreachable"
				}
				if now.Sub(checked) > 2*time.Minute {
					v.State = "stale"
				}
			} else if now.Sub(r.QueuedAt) > 2*time.Minute {
				v.State = "stale"
			}
		}
		if !online {
			v.State = "unavailable"
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		return latencyPathKey(views[i].EntryID, views[i].LandingID, views[i].Port, views[i].Source, views[i].Address) < latencyPathKey(views[j].EntryID, views[j].LandingID, views[j].Port, views[j].Source, views[j].Address)
	})
	return views, nil
}
func (s *Store) LatencyExchange(ctx context.Context, certificate string, report *LatencyResult) (*LatencyProbe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entry, ok := s.nodes[certificate]
	if !ok || entry.Desired.Entry == nil {
		return nil, errors.New("control: latency entry identity required")
	}
	targets := s.latencyTargetsLocked()
	s.pruneLatenciesLocked(targets)
	now := time.Now().UTC()
	if report != nil {
		valid := report.Samples >= 0 && report.Samples <= 3 && (report.Samples == 0) == (report.LatencyMillis == nil)
		if report.LatencyMillis != nil {
			v := *report.LatencyMillis
			valid = valid && !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 3000
		}
		found := false
		for _, r := range s.latencies {
			if r.Probe.AttemptID != report.AttemptID || r.Target.Certificate != certificate {
				continue
			}
			if !valid || r.IssuedAt.IsZero() || now.Sub(r.IssuedAt) > 30*time.Second || !s.latencyOnlineLocked(r.Target, now) {
				return nil, errors.New("control: latency report refused")
			}
			if r.Result != nil && !reflect.DeepEqual(*r.Result, *report) {
				return nil, errors.New("control: latency result already received")
			}
			if r.Result == nil {
				copy := *report
				if report.LatencyMillis != nil {
					value := *report.LatencyMillis
					copy.LatencyMillis = &value
				}
				r.Result = &copy
				r.CheckedAt = now
				r.History = append(r.History, LatencySample{CheckedAt: now, LatencyMillis: copy.LatencyMillis, Samples: copy.Samples})
				if len(r.History) > latencyHistoryLimit {
					r.History = append([]LatencySample(nil), r.History[len(r.History)-latencyHistoryLimit:]...)
				}
				s.saveLatencyHistoryLocked(latencyTargetKey(r.Target), r.Target, r.History)
			}
			found = true
			break
		}
		if !found {
			return nil, errors.New("control: latency assignment changed")
		}
		return nil, nil
	}
	var next *latencyRecord
	for _, r := range s.latencies {
		if r.Target.Certificate != certificate || r.Result != nil || !s.latencyOnlineLocked(r.Target, now) || !r.IssuedAt.IsZero() && now.Sub(r.IssuedAt) < 30*time.Second {
			continue
		}
		if next == nil || r.QueuedAt.Before(next.QueuedAt) || r.QueuedAt.Equal(next.QueuedAt) && r.Probe.AttemptID < next.Probe.AttemptID {
			next = r
		}
	}
	if next == nil {
		return nil, nil
	}
	next.IssuedAt = now
	p := next.Probe
	return &p, nil
}
