package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/ipquality"
)

// QualityHistory is separate from authoritative accounts, traffic and desired
// state. An import cannot change configuration or imply current reachability.
type QualityHistory struct {
	Version int            `json:"version"`
	Checks  []QualityCheck `json:"checks"`
}
type QualityCheck struct {
	NodeID      string            `json:"nodeId"`
	Address     string            `json:"address"`
	ID          string            `json:"id"`
	State       string            `json:"state"`
	Error       string            `json:"error,omitempty"`
	Report      *ipquality.Report `json:"report,omitempty"`
	CheckedAt   string            `json:"checkedAt,omitempty"`
	UpdatedAt   string            `json:"updatedAt"`
	Certificate string            `json:"certificate,omitempty"`
	Revision    uint64            `json:"revision,omitempty"`
	ExpiresAt   time.Time         `json:"expiresAt,omitempty"`
}
type QualityTarget struct {
	Available bool   `json:"available"`
	NodeID    string `json:"nodeId"`
	RuntimeID string `json:"runtimeId"`
	Address   string `json:"address"`
}
type QualityView struct {
	QualityCheck
	Assessment ipquality.Assessment `json:"assessment"`
	Historical bool                 `json:"historical"`
}

func qualityPublic(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && ip.String() == address && glivela.CompositePublicIP(ip)
}

func (h QualityHistory) validate() error {
	if h.Version != 1 || len(h.Checks) > 4096 {
		return errors.New("invalid quality history")
	}
	seen := map[string]bool{}
	for _, v := range h.Checks {
		key := v.NodeID + "/" + v.Address
		if !glivela.ValidIdentifier(v.NodeID) || !qualityPublic(v.Address) || !glivela.ValidIdentifier(v.ID) || seen[key] {
			return errors.New("invalid quality identity")
		}
		seen[key] = true
		if _, err := time.Parse(time.RFC3339Nano, v.UpdatedAt); err != nil {
			return errors.New("invalid quality timestamp")
		}
		if v.CheckedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, v.CheckedAt); err != nil {
				return err
			}
		}
		if v.Report != nil && (ipquality.Result{Report: v.Report}).Validate(v.Address) != nil {
			return errors.New("invalid quality report")
		}
		switch v.State {
		case "pending", "running":
			if !glivela.ValidIdentity(v.Certificate) || v.Revision == 0 || v.ExpiresAt.IsZero() {
				return errors.New("invalid quality lease")
			}
		case "succeeded":
			if v.Report == nil || v.CheckedAt == "" {
				return errors.New("missing quality report")
			}
		case "failed":
		default:
			return errors.New("invalid quality state")
		}
		if len(v.Error) > 64 {
			return errors.New("invalid quality error")
		}
	}
	return nil
}
func (s *Store) qualityLocked() (QualityHistory, error) {
	// Polls read the single-writer cache; no repeated file I/O or decoding on
	// heartbeat-adjacent diagnostic requests. Clone the slice before mutations.
	if s.quality != nil {
		h := *s.quality
		h.Checks = slices.Clone(h.Checks)
		return h, nil
	}
	path := filepath.Join(filepath.Dir(s.path), "quality.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		s.quality = &QualityHistory{Version: 1, Checks: []QualityCheck{}}
		return *s.quality, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32<<20 {
		return QualityHistory{}, errors.New("unsafe quality file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return QualityHistory{}, err
	}
	var h QualityHistory
	if json.Unmarshal(b, &h) != nil || h.validate() != nil {
		return h, errors.New("invalid quality file")
	}
	saved := h
	s.quality = &saved
	h.Checks = slices.Clone(h.Checks)
	return h, nil
}
func (s *Store) saveQualityLocked(h QualityHistory) error {
	if err := h.validate(); err != nil {
		return err
	}
	b, err := json.Marshal(h)
	if err != nil || len(b) > 32<<20 {
		return errors.New("quality limit")
	}
	if err := replacePrivate(filepath.Dir(s.path), "quality.json", b); err != nil {
		s.quality = nil // Re-read durable state after an ambiguous post-rename error.
		return err
	}
	saved := h
	saved.Checks = slices.Clone(h.Checks)
	s.quality = &saved
	return nil
}

// Bind every diagnostic to an enrolled host/runtime. Advertised endpoints may
// be DNS names, so select exact public exit identities from retained host hints
// and prior reports as well. These are only expected-result constraints: the
// detector contacts fixed providers and must prove the same actual source IP.
// They never grant proxy, transport, configuration or publication authority.
func (s *Store) qualityTargetsLocked() []QualityTarget {
	out := []QualityTarget{}
	seen := map[string]bool{}
	add := func(node, runtime, address string) {
		key := node + "/" + address
		if qualityPublic(address) && !seen[key] {
			seen[key] = true
			available := false
			for cert, n := range s.nodes {
				if n.ID == runtime {
					last := s.qualityPolls[cert]
					available = !last.IsZero() && time.Since(last) < 20*time.Second && !n.ReportedAt.IsZero() && time.Since(n.ReportedAt) < time.Minute
				}
			}
			out = append(out, QualityTarget{NodeID: node, RuntimeID: runtime, Address: address, Available: available})
		}
	}
	for _, n := range s.nodes {
		if n.Desired.Landing != nil {
			add(n.ID, n.ID, n.Desired.Landing.EgressIP)
		}
		if n.Desired.Entry != nil && s.business != nil {
			for _, e := range s.business.material.Endpoints {
				if e.Reality.EntryID != n.ID || e.Retired {
					continue
				}
				service := s.business.material.References.Services[e.ServiceID]
				host := s.business.material.References.Applications[service.ApplicationID].NodeID
				if host != "" {
					add(host, n.ID, e.Reality.AdvertiseHost)
					ref := s.business.material.References.Nodes[host]
					add(host, n.ID, ref.ServiceAddress)
					var interfaces []struct {
						Address string `json:"address"`
					}
					if json.Unmarshal(ref.EgressAddressesJSON, &interfaces) == nil && len(interfaces) <= 128 {
						for _, candidate := range interfaces {
							add(host, n.ID, candidate.Address)
						}
					}
					if history, err := s.qualityLocked(); err == nil {
						for _, check := range history.Checks {
							if check.NodeID == host && check.Report != nil {
								add(host, n.ID, check.Address)
							}
						}
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID+out[i].Address < out[j].NodeID+out[j].Address })
	return out
}
func (s *Store) manageQuality(w http.ResponseWriter, r *http.Request) {
	var in struct {
		NodeID  string          `json:"nodeId"`
		Address string          `json:"address"`
		Import  *QualityHistory `json:"import,omitempty"`
	}
	if decode(http.MaxBytesReader(w, r.Body, 32<<20), &in) != nil {
		http.Error(w, "invalid quality request", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.qualityLocked()
	if err != nil {
		http.Error(w, "quality history unavailable", 500)
		return
	}
	now := time.Now().UTC()
	targets := s.qualityTargetsLocked()
	if in.Import != nil {
		// Explicit administrator-only, idempotent insert. Never overwrite a newer
		// or existing record, nor silently omit an unknown/retired host's history.
		if in.NodeID != "" || in.Address != "" || in.Import.validate() != nil {
			http.Error(w, "invalid history import", 400)
			return
		}
		known := map[string]bool{}
		for _, v := range h.Checks {
			known[v.NodeID+"/"+v.Address] = true
		}
		for _, v := range in.Import.Checks {
			if v.State == "pending" || v.State == "running" || v.Certificate != "" || v.Revision != 0 || !v.ExpiresAt.IsZero() {
				http.Error(w, "import cannot grant probe authority", 400)
				return
			}
			if !known[v.NodeID+"/"+v.Address] {
				h.Checks = append(h.Checks, v)
			}
		}
		if s.saveQualityLocked(h) != nil {
			http.Error(w, "history import not saved", 500)
			return
		}
	} else if in.NodeID != "" {
		var target *QualityTarget
		for i := range targets {
			if targets[i].NodeID == in.NodeID && targets[i].Address == in.Address {
				target = &targets[i]
			}
		}
		if target == nil || !target.Available {
			http.Error(w, "quality target not enrolled", 409)
			return
		}
		var node Node
		for _, n := range s.nodes {
			if n.ID == target.RuntimeID {
				node = n
			}
		}
		if node.ReportedAt.IsZero() || now.Sub(node.ReportedAt) > time.Minute {
			http.Error(w, "quality node offline", 409)
			return
		}
		for _, v := range h.Checks {
			if v.Certificate == node.CertificateID && (v.State == "pending" || v.State == "running") && now.Before(v.ExpiresAt) {
				http.Error(w, "quality check already active", 409)
				return
			}
		}
		record := QualityCheck{NodeID: in.NodeID, Address: in.Address, ID: uuid.NewString(), State: "pending", UpdatedAt: now.Format(time.RFC3339Nano), Certificate: node.CertificateID, Revision: node.Desired.Revision, ExpiresAt: now.Add(5 * time.Minute)}
		found := false
		for i, v := range h.Checks {
			if v.NodeID == in.NodeID && v.Address == in.Address {
				record.Report = v.Report
				record.CheckedAt = v.CheckedAt
				h.Checks[i] = record
				found = true
			}
		}
		if !found {
			h.Checks = append(h.Checks, record)
		}
		if s.saveQualityLocked(h) != nil {
			http.Error(w, "quality check not saved", 500)
			return
		}
		s.nodeEvents.wake(node.CertificateID, nodeSignalQuality)
	}
	views := []QualityView{}
	for _, v := range h.Checks {
		historical := true
		for _, t := range targets {
			if t.NodeID == v.NodeID && t.Address == v.Address {
				historical = false
			}
		}
		if (v.State == "pending" || v.State == "running") && !now.Before(v.ExpiresAt) {
			v.State = "failed"
			v.Error = "timeout"
		}
		v.Certificate = ""
		v.Revision = 0
		v.ExpiresAt = time.Time{}
		views = append(views, QualityView{v, ipquality.Assess(v.Report, v.CheckedAt, historical, now, ipquality.DefaultPreferences()), historical})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Checks  []QualityView   `json:"checks"`
		Targets []QualityTarget `json:"targets"`
	}{views, targets})
}
