package control

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

const observatoryPollInterval = 15 * time.Second

// ObservatoryPathStatus records Xray burstObservatory health for one exact
// full path (entry -> relay -> fixed landing). It is display-only telemetry and
// never triggers configuration reloads or node restarts.
type ObservatoryPathStatus struct {
	PoolID          string `json:"poolId"`
	RelayNodeID     string `json:"relayNodeId"`
	EgressID        string `json:"egressId"`
	OutboundTag     string `json:"outboundTag"`
	Alive           bool   `json:"alive"`
	DelayMS         int64  `json:"delayMs"`
	LastErrorReason string `json:"lastErrorReason,omitempty"`
	LastSeenTime    int64  `json:"lastSeenTime,omitempty"`
	LastTryTime     int64  `json:"lastTryTime,omitempty"`
	AllSamples      int64  `json:"allSamples,omitempty"`
	FailedSamples   int64  `json:"failedSamples,omitempty"`
	AverageMS       int64  `json:"averageMs,omitempty"`
	MinMS           int64  `json:"minMs,omitempty"`
	MaxMS           int64  `json:"maxMs,omitempty"`
}

// EntryObservatoryReport is an entry's low-frequency snapshot of local Xray
// burstObservatory status carried over the existing node Exchange RPC.
type EntryObservatoryReport struct {
	SampledAt time.Time               `json:"sampledAt"`
	Paths     []ObservatoryPathStatus `json:"paths"`
}

// EntryObservatoryPathView is the secret-free controller inventory view for one
// full (entry, pool, relay, landing) path.
type EntryObservatoryPathView struct {
	EntryID         string    `json:"entryId"`
	GrantID         string    `json:"grantId,omitempty"`
	PoolID          string    `json:"poolId"`
	RelayNodeID     string    `json:"relayNodeId"`
	EgressID        string    `json:"egressId"`
	OutboundTag     string    `json:"outboundTag"`
	Alive           bool      `json:"alive"`
	DelayMS         int64     `json:"delayMs"`
	AverageMS       int64     `json:"averageMs,omitempty"`
	MinMS           int64     `json:"minMs,omitempty"`
	MaxMS           int64     `json:"maxMs,omitempty"`
	AllSamples      int64     `json:"allSamples,omitempty"`
	FailedSamples   int64     `json:"failedSamples,omitempty"`
	LastErrorReason string    `json:"lastErrorReason,omitempty"`
	SampledAt       time.Time `json:"sampledAt"`
}

func (r *EntryObservatoryReport) clone() *EntryObservatoryReport {
	if r == nil {
		return nil
	}
	copyReport := *r
	copyReport.Paths = slices.Clone(r.Paths)
	return &copyReport
}

type nativeObservatoryCache struct {
	mu          sync.Mutex
	generation  string
	lastQueryAt time.Time
	report      *EntryObservatoryReport
	queryFn     func(context.Context, string) (map[string]landing.ObservatoryOutboundStatus, error)
}

func (d *NativeEntryDriver) observatoryFromProcess(ctx context.Context, desired Desired, process nativeEntryProcess) *EntryObservatoryReport {
	if desired.Entry == nil || !hasObservableCandidates(*desired.Entry) {
		return nil
	}
	gen := fmt.Sprintf("%d:%s:%s:%d:%s", process.PID, process.Invocation, process.StartedAt, desired.Revision, desired.ConfigSHA256)
	now := time.Now().UTC()
	d.observatory.mu.Lock()
	if d.observatory.generation == gen && !d.observatory.lastQueryAt.IsZero() && now.Sub(d.observatory.lastQueryAt) < observatoryPollInterval && now.Sub(d.observatory.lastQueryAt) >= 0 {
		cached := d.observatory.report.clone()
		d.observatory.mu.Unlock()
		return cached
	}
	// Record attempt timestamp before querying so continuous API failures also
	// respect the 15s throttle instead of blocking every health check for 2s.
	d.observatory.generation = gen
	d.observatory.lastQueryAt = now
	d.observatory.report = nil
	query := d.observatory.queryFn
	d.observatory.mu.Unlock()

	if query == nil {
		query = landing.QueryObservatoryStatus
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	statuses, err := query(queryCtx, fmt.Sprintf("127.0.0.1:%d", glivela.XrayAPIListenPort))
	cancel()
	if err != nil {
		// Telemetry read failure never degrades RuntimeReady or triggers restarts.
		return nil
	}
	report := buildEntryObservatoryReport(*desired.Entry, statuses, time.Now().UTC())
	d.observatory.mu.Lock()
	if d.observatory.generation == gen {
		d.observatory.report = report.clone()
	}
	d.observatory.mu.Unlock()
	return report
}

func hasObservableCandidates(plan glivela.XrayPlan) bool {
	for _, pool := range plan.RelayPools {
		if len(pool.Candidates) > 0 {
			return true
		}
	}
	return false
}

func buildEntryObservatoryReport(plan glivela.XrayPlan, statuses map[string]landing.ObservatoryOutboundStatus, sampledAt time.Time) *EntryObservatoryReport {
	paths := []ObservatoryPathStatus{}
	for _, pool := range plan.RelayPools {
		for idx, cand := range pool.Candidates {
			tag := glivela.PoolCandidateTag(pool.Key, idx)
			st, ok := statuses[tag]
			if !ok {
				continue
			}
			delay := st.DelayMS
			if delay < 0 {
				delay = 0
			}
			if delay > 60000 {
				delay = 60000
			}
			reason := strings.TrimSpace(st.LastErrorReason)
			if len(reason) > 256 {
				reason = reason[:256]
			}
			reason = strings.Map(func(r rune) rune {
				if r == '\x00' || r == '\r' || r == '\n' {
					return ' '
				}
				return r
			}, reason)
			item := ObservatoryPathStatus{
				PoolID:          pool.PoolID,
				RelayNodeID:     cand.RelayNodeID,
				EgressID:        pool.EgressID,
				OutboundTag:     tag,
				Alive:           st.Alive,
				DelayMS:         delay,
				LastErrorReason: reason,
				LastSeenTime:    st.LastSeenTime,
				LastTryTime:     st.LastTryTime,
			}
			if st.HealthPing != nil {
				item.AllSamples = max(int64(0), st.HealthPing.All)
				item.FailedSamples = min(item.AllSamples, max(int64(0), st.HealthPing.Fail))
				item.AverageMS = clampObservatoryMS(st.HealthPing.Average.Milliseconds())
				item.MinMS = clampObservatoryMS(st.HealthPing.Min.Milliseconds())
				item.MaxMS = clampObservatoryMS(st.HealthPing.Max.Milliseconds())
			}
			paths = append(paths, item)
		}
	}
	slices.SortFunc(paths, func(a, b ObservatoryPathStatus) int { return strings.Compare(a.OutboundTag, b.OutboundTag) })
	return &EntryObservatoryReport{SampledAt: sampledAt, Paths: paths}
}

func clampObservatoryMS(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > 60000 {
		return 60000
	}
	return v
}

func validateEntryObservatory(desired Desired, report *EntryObservatoryReport) error {
	if report == nil {
		return nil
	}
	invalid := errors.New("control: invalid entry observatory report")
	if report.SampledAt.IsZero() || desired.Entry == nil || len(report.Paths) > 4096 {
		return invalid
	}
	expected := map[string]struct{ poolID, relayID, egressID string }{}
	for _, pool := range desired.Entry.RelayPools {
		for idx, cand := range pool.Candidates {
			tag := glivela.PoolCandidateTag(pool.Key, idx)
			expected[tag] = struct{ poolID, relayID, egressID string }{pool.PoolID, cand.RelayNodeID, pool.EgressID}
		}
	}
	if len(expected) == 0 && len(report.Paths) > 0 {
		return invalid
	}
	seen := map[string]bool{}
	for _, p := range report.Paths {
		want, ok := expected[p.OutboundTag]
		if !ok || seen[p.OutboundTag] || p.PoolID != want.poolID || p.RelayNodeID != want.relayID || p.EgressID != want.egressID {
			return invalid
		}
		if p.DelayMS < 0 || p.DelayMS > 60000 || p.AverageMS < 0 || p.AverageMS > 60000 || p.MinMS < 0 || p.MinMS > 60000 || p.MaxMS < 0 || p.MaxMS > 60000 || p.AllSamples < 0 || p.FailedSamples < 0 || p.FailedSamples > p.AllSamples || len(p.LastErrorReason) > 256 || strings.ContainsAny(p.LastErrorReason, "\x00\r\n") {
			return invalid
		}
		seen[p.OutboundTag] = true
	}
	return nil
}

func (s *Store) observatoryPathViewsLocked() []EntryObservatoryPathView {
	views := []EntryObservatoryPathView{}
	for _, node := range s.nodes {
		if node.Desired.Entry == nil || node.Receipt == nil || node.Receipt.Observatory == nil {
			continue
		}
		tagGrant := map[string]string{}
		for _, pool := range node.Desired.Entry.RelayPools {
			for idx := range pool.Candidates {
				tagGrant[glivela.PoolCandidateTag(pool.Key, idx)] = pool.GrantID
			}
		}
		obs := node.Receipt.Observatory
		for _, p := range obs.Paths {
			views = append(views, EntryObservatoryPathView{
				EntryID:         node.ID,
				GrantID:         tagGrant[p.OutboundTag],
				PoolID:          p.PoolID,
				RelayNodeID:     p.RelayNodeID,
				EgressID:        p.EgressID,
				OutboundTag:     p.OutboundTag,
				Alive:           p.Alive,
				DelayMS:         p.DelayMS,
				AverageMS:       p.AverageMS,
				MinMS:           p.MinMS,
				MaxMS:           p.MaxMS,
				AllSamples:      p.AllSamples,
				FailedSamples:   p.FailedSamples,
				LastErrorReason: p.LastErrorReason,
				SampledAt:       obs.SampledAt,
			})
		}
	}
	slices.SortFunc(views, func(a, b EntryObservatoryPathView) int {
		if c := strings.Compare(a.EntryID, b.EntryID); c != 0 {
			return c
		}
		if c := strings.Compare(a.PoolID, b.PoolID); c != 0 {
			return c
		}
		if c := strings.Compare(a.EgressID, b.EgressID); c != 0 {
			return c
		}
		if c := strings.Compare(a.RelayNodeID, b.RelayNodeID); c != 0 {
			return c
		}
		return strings.Compare(a.OutboundTag, b.OutboundTag)
	})
	return views
}
