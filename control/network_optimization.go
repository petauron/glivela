package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	pb "github.com/petauron/glivela/internal/controlpb"
	"net/http"
	"sort"
	"time"
)

// Network optimization is separate from proxy desired state and accounting.
// Only administrator requests create mutations; nodes cannot nominate targets.
type NetworkSnapshot struct {
	CheckedAt        time.Time `json:"checkedAt"`
	Fingerprint      string    `json:"fingerprint"`
	Scope            string    `json:"scope"`
	Observed         bool      `json:"observed"`
	Kernel           string    `json:"kernel"`
	QdiscFingerprint string    `json:"qdiscFingerprint"`
	Interface        string    `json:"interface"`
	MTU              int       `json:"mtu"`
	MemoryBytes      int64     `json:"memoryBytes"`
	Congestion       string    `json:"congestion"`
	Available        []string  `json:"available"`
	DefaultQdisc     string    `json:"defaultQdisc"`
	Qdisc            string    `json:"qdisc"`
	Send             [3]int64  `json:"send"`
	Receive          [3]int64  `json:"receive"`
	SendMax          int64     `json:"sendMax"`
	ReceiveMax       int64     `json:"receiveMax"`
	Scaling          int       `json:"scaling"`
	AutoReceive      int       `json:"autoReceive"`
	CanApply         bool      `json:"canApply"`
	CanRestore       bool      `json:"canRestore"`
	Reason           string    `json:"reason,omitempty"`
}
type NetworkCommand struct {
	PathMTU     *PathMTUCommand `json:"pathMtu,omitempty"`
	ID          string          `json:"id"`
	Action      string          `json:"action"`
	Expected    string          `json:"expected"`
	BufferBytes int64           `json:"bufferBytes"`
	ExpiresAt   time.Time       `json:"expiresAt"`
	Actor       string          `json:"actor"`
}
type NetworkResult struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
}
type NetworkSettings struct {
	Paths map[string]PathMTUObservation `json:"paths,omitempty"`
	// Preserve prior settings in persisted state; buffer calculation uses memory only.
	BandwidthMbps   int             `json:"bandwidthMbps"`
	ManualRTTMillis float64         `json:"manualRttMs,omitempty"`
	RegionCode      string          `json:"regionCode,omitempty"`
	Path            string          `json:"path"`
	Revision        uint64          `json:"revision,string"`
	Command         *NetworkCommand `json:"command,omitempty"`
	Result          *NetworkResult  `json:"result,omitempty"`
}
type NetworkReport struct {
	PathMTUSupported bool                 `json:"pathMtuSupported,omitempty"`
	Paths            []PathMTUObservation `json:"paths,omitempty"`
	Snapshot         NetworkSnapshot      `json:"snapshot"`
	Result           *NetworkResult       `json:"result,omitempty"`
}
type NetworkView struct {
	NodeID          string           `json:"nodeId"`
	Settings        NetworkSettings  `json:"settings"`
	Snapshot        *NetworkSnapshot `json:"snapshot,omitempty"`
	State           string           `json:"state"`
	AutoBufferBytes int64            `json:"autoBufferBytes,omitempty"`
}

func networkDigest(v NetworkSnapshot) string {
	v.CheckedAt = time.Time{}
	v.Fingerprint = ""
	v.CanRestore = false
	v.Reason = ""
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// networkAutoBuffer estimates a conservative ceiling from the node's memory.
func networkAutoBuffer(report NetworkSnapshot) int64 {
	if !report.Observed {
		return 0
	}
	const mib = int64(1 << 20)
	cap := min(report.MemoryBytes/32, 256*mib) / mib * mib
	if cap < 4*mib {
		return 0
	}
	// Use one MiB per started 64 MiB of actual RAM, subject to the safety cap.
	steps := report.MemoryBytes / (64 * mib)
	if report.MemoryBytes%(64*mib) != 0 {
		steps++
	}
	return min(max(steps*mib, 4*mib), cap)
}

func (s *Store) networkViewsLocked() []NetworkView {
	now := time.Now().UTC()
	out := make([]NetworkView, 0, len(s.nodes))
	for _, n := range s.nodes {
		if s.entryRetiredLocked(n.ID) {
			continue
		}
		v := NetworkView{NodeID: n.ID, State: "unknown"}
		if n.Network != nil {
			v.Settings = *n.Network
		}
		if r, ok := s.networkReports[n.CertificateID]; ok {
			snap := r
			v.Snapshot = &snap
			v.State = "ready"
			if now.Sub(r.CheckedAt) > 2*time.Minute || !s.availableRuntime(n, now) {
				v.State = "stale"
			} else {
				v.AutoBufferBytes = networkAutoBuffer(r)
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}
func (s *Store) manageNetwork(w http.ResponseWriter, r *http.Request) {
	var input struct {
		NodeID           string `json:"nodeId"`
		Action           string `json:"action"`
		ExpectedRevision uint64 `json:"expectedRevision,string"`
		Expected         string `json:"expected"`
		BufferBytes      int64  `json:"bufferBytes"`
		Confirm          bool   `json:"confirm"`
	}
	if decode(http.MaxBytesReader(w, r.Body, 8192), &input) != nil {
		http.Error(w, "invalid network request", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(message string) { http.Error(w, message, http.StatusConflict) }
	if input.Action != "list" {
		cert := ""
		var n Node
		for key, v := range s.nodes {
			if v.ID == input.NodeID {
				cert = key
				n = v
				break
			}
		}
		if cert == "" || s.entryRetiredLocked(n.ID) {
			fail("node is not enrolled")
			return
		}
		settings := NetworkSettings{}
		if n.Network != nil {
			settings = *n.Network
		}
		if settings.Revision != input.ExpectedRevision {
			fail("settings changed; refresh first")
			return
		}
		if settings.Command != nil && time.Now().Before(settings.Command.ExpiresAt) && (settings.Result == nil || settings.Result.ID != settings.Command.ID) {
			fail("operation in progress")
			return
		}
		if input.Action == "inspect" || input.Action == "apply" || input.Action == "restore" {
			if !s.availableRuntime(n, time.Now()) {
				fail("node offline or runtime unverified")
				return
			}
			if input.Action != "inspect" {
				snap, ok := s.networkReports[cert]
				if !input.Confirm || !ok || time.Since(snap.CheckedAt) > 2*time.Minute || snap.Fingerprint != input.Expected {
					fail("fresh inspection and confirmation required")
					return
				}
				if input.Action == "apply" && !snap.CanApply || input.Action == "restore" && !snap.CanRestore {
					fail("operation unavailable; inspect node reason")
					return
				}
				if input.Action == "apply" {
					suggestion := networkAutoBuffer(snap)
					if suggestion == 0 || input.BufferBytes != suggestion {
						fail("memory-based buffer suggestion unavailable or changed; refresh first")
						return
					}
				}
			}
			id, err := newRouteAttempt()
			if err != nil {
				fail("cannot create operation")
				return
			}
			settings.Command = &NetworkCommand{ID: id, Action: input.Action, Expected: input.Expected, BufferBytes: input.BufferBytes, ExpiresAt: time.Now().UTC().Add(2 * time.Minute), Actor: CertificateID(r.TLS.PeerCertificates[0])}
			settings.Result = nil
		} else {
			http.Error(w, "unknown network action", 400)
			return
		}
		settings.Revision++
		n.Network = &settings
		next := s.copy()
		next[cert] = n
		if s.commit(next) != nil {
			fail("settings not saved")
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"nodes": s.networkViewsLocked()})
}
func (s *Store) exchangeNetwork(cert string, report *NetworkReport) (*NetworkCommand, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[cert]
	if !ok {
		return nil, errors.New("node not enrolled")
	}
	if report != nil {
		if err := s.acceptPathMTUReport(cert, n, report); err != nil {
			return nil, err
		}
		v := report.Snapshot
		if len(v.Reason) > 512 || len(v.Interface) > 64 || len(v.Scope) > 80 || len(v.Available) > 32 || len(v.Fingerprint) != 64 {
			return nil, errors.New("invalid network observation")
		}
		if v.CheckedAt.IsZero() || time.Since(v.CheckedAt) > 2*time.Minute || time.Until(v.CheckedAt) > time.Minute {
			return nil, errors.New("stale network observation")
		}
		if s.networkReports == nil {
			s.networkReports = map[string]NetworkSnapshot{}
		}
		s.networkReports[cert] = v
		if result := report.Result; result != nil {
			if len(result.ID) > 128 || len(result.Message) > 512 || result.State != "succeeded" && result.State != "failed" {
				return nil, errors.New("unexpected network receipt")
			}
			// Late receipts from expired/replaced commands must not wedge this channel.
			if n.Network != nil && n.Network.Command != nil && result.ID == n.Network.Command.ID && n.Network.Result == nil {
				settings := *n.Network
				recordPathMTU(&settings, report)
				settings.Result = result
				n.Network = &settings
				next := s.copy()
				next[cert] = n
				if err := s.commit(next); err != nil {
					return nil, err
				}
			}
		}
	}
	if n.Network == nil || n.Network.Command == nil || n.Network.Result != nil || time.Now().After(n.Network.Command.ExpiresAt) {
		return nil, nil
	}
	command := *n.Network.Command
	return &command, nil
}
func (c *Client) networkExchange(ctx context.Context, report *NetworkReport) (*NetworkCommand, error) {
	var out struct {
		Command *NetworkCommand `json:"command"`
	}
	if err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).NetworkOptimization, struct {
		Report *NetworkReport `json:"report"`
	}{report}, &out, 64<<10, 8192); err != nil {
		return nil, err
	}
	return out.Command, nil
}
