package control

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
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
	Port      int    `json:"port"`
}

func (p LatencyProbe) Validate() error {
	a, err := netip.ParseAddr(p.Address)
	if !glivela.ValidIdentifier(p.AttemptID) || !glivela.ValidIdentifier(p.EntryID) || !glivela.ValidIdentifier(p.LandingID) || err != nil || a.String() != p.Address || a.Zone() != "" || !a.IsGlobalUnicast() || p.Port != landing.SOCKSPort && (p.Port < 24000 || p.Port > 24999) {
		return errors.New("control: invalid latency assignment")
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
			if !ok {
				continue
			}
			enrolled, ok := node.RouteEntries[entry.ID]
			if !ok || enrolled.CertificateID != cert || peer.Transport != node.Desired.Landing.Transport || peer.Address != node.Desired.Landing.Address {
				continue
			}
			target := latencyTarget{Certificate: cert, EntryRevision: entry.Desired.Revision, LandingRevision: node.Desired.Revision, EntryHash: entry.Desired.ConfigSHA256, LandingHash: node.Desired.ConfigSHA256, Address: peer.Transport.Endpoint(peer.Address), EntryID: entry.ID, LandingID: node.ID, Port: landing.SOCKSPort}
			out[latencyKey(entry.ID, node.ID, target.Port)] = target
			if s.business != nil && s.business.material.Ownership != nil && !s.business.faulted {
				for _, original := range s.business.material.ClientChains {
					chain, err := s.business.material.EffectiveClientChain(original)
					if err != nil {
						continue
					}
					if chain.Enabled && chain.EntryID == entry.ID && chain.EgressID == node.ID {
						for _, listener := range node.Desired.Landing.ClientListeners {
							if listener.ID == chain.ID && listener.Port == chain.Port {
								t := target
								t.Address = peer.Transport.PublicAddress
								t.Port = chain.Port
								if (LatencyProbe{AttemptID: "latency", EntryID: t.EntryID, LandingID: t.LandingID, Address: t.Address, Port: t.Port}).Validate() == nil {
									out[latencyKey(entry.ID, node.ID, t.Port)] = t
								}
							}
						}
					}
				}
			}
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
			p := LatencyProbe{AttemptID: attempt, EntryID: t.EntryID, LandingID: t.LandingID, Address: t.Address, Port: t.Port}
			if p.Validate() != nil {
				continue
			}
			r = &latencyRecord{Target: t, Probe: p, QueuedAt: now, History: history}
			s.latencies[k] = r
		}
		v := LatencyView{EntryID: t.EntryID, LandingID: t.LandingID, Port: t.Port, State: "unknown", History: append([]LatencySample(nil), history...), HistoryUnavailable: s.latencyHistoryFault}
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
		return latencyKey(views[i].EntryID, views[i].LandingID, views[i].Port) < latencyKey(views[j].EntryID, views[j].LandingID, views[j].Port)
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
				s.saveLatencyHistoryLocked(latencyKey(r.Target.EntryID, r.Target.LandingID, r.Target.Port), r.Target, r.History)
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
