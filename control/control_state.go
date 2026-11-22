package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const controlStateLimit = 2 << 20

func readControlState(path string, target any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > controlStateLimit {
		return errors.New("unsafe control state")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, target) != nil {
		return errors.New("invalid control state")
	}
	return nil
}
func writeControlState(path string, value any) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("unsafe control state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > controlStateLimit {
		return errors.New("control state limit exceeded")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".control-state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Deliberately excludes all temporary iperf passwords and keys. Restart does
// not re-run an interrupted diagnostic: clean both endpoints and report failure.
type speedDiskRecord struct {
	SubmittedBy        string
	Request            SpeedRequest
	View               SpeedView
	Target             latencyTarget
	LandingCertificate string
	Source             string
	Issued             map[string]bool
	Reports            map[string]SpeedReport
	Phase              string
	ClientClean        bool
	Progress           map[string]*SpeedProgress
}
type speedState struct {
	Version  int
	Revision uint64
	Jobs     map[string]speedDiskRecord
}

func (s *Store) speedStatePath() string {
	return filepath.Join(filepath.Dir(s.path), "speed-tasks.json")
}
func (s *Store) loadSpeedState() error {
	var disk speedState
	err := readControlState(s.speedStatePath(), &disk)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if disk.Version != 1 || len(disk.Jobs) > 32 || disk.Revision == 0 {
		return errors.New("invalid speed state")
	}
	s.speedJobs = map[string]*speedRecord{}
	s.speedRevision = disk.Revision
	changed := false
	for id, d := range disk.Jobs {
		if !speedID(id) || d.Request.ID != id || d.View.ID != id || !speedModes(d.Request.Modes) || d.Issued == nil || d.Reports == nil || len(d.Progress) > 4 || !speedRole(d.Phase) && d.Phase != "done" || d.View.StartedAt.IsZero() {
			return errors.New("invalid speed task")
		}
		r := &speedRecord{SubmittedBy: d.SubmittedBy, Request: d.Request, View: d.View, Target: d.Target, LandingCertificate: d.LandingCertificate, Source: d.Source, Issued: d.Issued, Reports: d.Reports, Phase: d.Phase, ClientClean: d.ClientClean, Progress: d.Progress}
		if r.Progress == nil {
			r.Progress = map[string]*SpeedProgress{}
		}
		if r.Phase != "done" {
			r.Phase = "client-cleanup"
			r.View.State = "cleaning"
			r.View.Error = "controller_restarted"
			delete(r.Reports, "client-cleanup")
			delete(r.Issued, "client-cleanup")
			changed = true
		}
		s.speedJobs[id] = r
	}
	if changed {
		return s.saveSpeedLocked()
	}
	return nil
}
func speedRole(role string) bool {
	return role == "receiver" || role == "client" || role == "cleanup" || role == "client-cleanup"
}

const (
	speedWatchWait        = 10 * time.Second
	speedWatchWriteMargin = 15 * time.Second
)

type speedWatchNode struct {
	certificate string
	id          string
}
type speedWatchSnapshot struct {
	initialized bool
	fault       bool
	revision    uint64
	tests       []SpeedView
	nodes       []speedWatchNode
	hub         *speedHub
	nextExpiry  time.Time
	changed     chan struct{}
}

func cloneTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}
func cloneUint64Ptr(v *uint64) *uint64 {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}
func cloneSpeedSample(v *SpeedSample) *SpeedSample {
	if v == nil {
		return nil
	}
	copyValue := *v
	copyValue.Retransmits = cloneUint64Ptr(v.Retransmits)
	return &copyValue
}
func cloneSpeedMeasurement(v *SpeedMeasurement) *SpeedMeasurement {
	if v == nil {
		return nil
	}
	copyValue := *v
	copyValue.Upload = cloneSpeedSample(v.Upload)
	copyValue.Download = cloneSpeedSample(v.Download)
	return &copyValue
}
func cloneSpeedProgress(in []SpeedProgress) []SpeedProgress {
	if len(in) == 0 {
		return nil
	}
	out := make([]SpeedProgress, len(in))
	for i, p := range in {
		out[i] = SpeedProgress{
			Role:        p.Role,
			ReceivedAt:  cloneTimePtr(p.ReceivedAt),
			RunningAt:   cloneTimePtr(p.RunningAt),
			FinishedAt:  cloneTimePtr(p.FinishedAt),
			ConfirmedAt: cloneTimePtr(p.ConfirmedAt),
		}
	}
	return out
}
func cloneSpeedView(v SpeedView) SpeedView {
	if v.Modes != nil {
		v.Modes = append([]string{}, v.Modes...)
	}
	v.Progress = cloneSpeedProgress(v.Progress)
	v.FinishedAt = cloneTimePtr(v.FinishedAt)
	v.Direct = cloneSpeedMeasurement(v.Direct)
	v.SS2022 = cloneSpeedMeasurement(v.SS2022)
	v.EntryWireBytes = cloneUint64Ptr(v.EntryWireBytes)
	v.LandingWireBytes = cloneUint64Ptr(v.LandingWireBytes)
	if v.Policy != nil {
		copyValue := *v.Policy
		v.Policy = &copyValue
	}
	if len(v.Points) > 0 {
		v.Points = append([]SpeedPoint(nil), v.Points...)
	} else {
		v.Points = nil
	}
	return v
}
func cloneSpeedViews(in []SpeedView) []SpeedView {
	out := make([]SpeedView, len(in))
	for i, v := range in {
		out[i] = cloneSpeedView(v)
	}
	return out
}
func (s *Store) speedWatchNodesLocked() []speedWatchNode {
	out := make([]speedWatchNode, 0, len(s.nodes))
	for certificate, node := range s.nodes {
		out = append(out, speedWatchNode{certificate: certificate, id: node.ID})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].id != out[j].id {
			return out[i].id < out[j].id
		}
		return out[i].certificate < out[j].certificate
	})
	return out
}
func speedChannelsFromNodes(nodes []speedWatchNode, hub *speedHub) []SpeedChannel {
	out := make([]SpeedChannel, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, SpeedChannel{ID: node.id, Connected: hub != nil && hub.online(node.certificate)})
	}
	return out
}
func (s *Store) speedNextExpiryLocked() time.Time {
	var next time.Time
	for _, r := range s.speedJobs {
		if r.Phase == "done" || r.Phase == "cleanup" || r.Phase == "client-cleanup" {
			continue
		}
		expiry := r.View.StartedAt.Add(speedLease)
		if next.IsZero() || expiry.Before(next) {
			next = expiry
		}
	}
	return next
}
func (s *Store) publishSpeedStateLocked() {
	tests := cloneSpeedViews(s.speedViewsLocked())
	nodes := s.speedWatchNodesLocked()
	nextExpiry := s.speedNextExpiryLocked()
	fault := s.speedFault
	revision := s.speedRevision
	hub := s.speedHub

	s.speedViewMu.Lock()
	wake := s.speedView.initialized && (s.speedView.revision != revision || s.speedView.fault != fault)
	if s.speedView.changed == nil {
		s.speedView.changed = make(chan struct{})
	}
	s.speedView.initialized = true
	s.speedView.fault = fault
	s.speedView.revision = revision
	s.speedView.tests = tests
	s.speedView.nodes = nodes
	s.speedView.hub = hub
	s.speedView.nextExpiry = nextExpiry
	if wake {
		close(s.speedView.changed)
		s.speedView.changed = make(chan struct{})
	}
	s.speedViewMu.Unlock()
}
func (s *Store) publishSpeedNodesLocked() {
	s.speedViewMu.Lock()
	if !s.speedView.initialized {
		s.speedViewMu.Unlock()
		s.publishSpeedStateLocked()
		return
	}
	same := s.speedView.hub == s.speedHub && len(s.speedView.nodes) == len(s.nodes)
	if same {
		for _, node := range s.speedView.nodes {
			current, ok := s.nodes[node.certificate]
			if !ok || current.ID != node.id {
				same = false
				break
			}
		}
	}
	if same {
		s.speedViewMu.Unlock()
		return
	}
	s.speedViewMu.Unlock()

	nodes := s.speedWatchNodesLocked()
	hub := s.speedHub
	s.speedViewMu.Lock()
	s.speedView.nodes = nodes
	s.speedView.hub = hub
	s.speedViewMu.Unlock()
}
func (s *Store) watchSpeedWait() time.Duration {
	s.speedViewMu.Lock()
	wait := s.speedWatchTimeout
	s.speedViewMu.Unlock()
	if wait > 0 {
		return wait
	}
	return speedWatchWait
}
func (s *Store) saveSpeedLocked() error {
	if s.speedFault {
		s.publishSpeedStateLocked()
		return errors.New("speed_state_unavailable")
	}
	s.speedRevision++
	jobs := map[string]speedDiskRecord{}
	for id, r := range s.speedJobs {
		jobs[id] = speedDiskRecord{r.SubmittedBy, r.Request, r.View, r.Target, r.LandingCertificate, r.Source, r.Issued, r.Reports, r.Phase, r.ClientClean, r.Progress}
	}
	if err := writeControlState(s.speedStatePath(), speedState{1, s.speedRevision, jobs}); err != nil {
		s.speedFault = true
		s.publishSpeedStateLocked()
		return errors.New("speed_state_unavailable")
	}
	s.publishSpeedStateLocked()
	s.wakeSpeedParticipantsLocked("")
	return nil
}

type SpeedProgress struct {
	Role        string     `json:"role"`
	ReceivedAt  *time.Time `json:"receivedAt,omitempty"`
	RunningAt   *time.Time `json:"runningAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	ConfirmedAt *time.Time `json:"confirmedAt,omitempty"`
}
type SpeedChannel struct {
	ID        string `json:"id"`
	Connected bool   `json:"connected"`
}

type SpeedList struct {
	Channels []SpeedChannel `json:"channels"`
	Revision uint64         `json:"revision,string"`
	Tests    []SpeedView    `json:"tests"`
	Policy   SpeedPolicy    `json:"policy"`
}

// Event-driven HTTP wait fits the existing authenticated facade. New task
// revisions wake it immediately; there is no browser fixed-interval poll.
// Reads use the detached speed snapshot so unrelated Store.mu disk/backup work
// cannot starve long-poll responses past HTTP server or proxy header deadlines.
func (s *Store) WatchSpeeds(ctx context.Context, after *uint64) (SpeedList, error) {
	var timer *time.Timer
	var timerC <-chan time.Time
	if after != nil {
		timer = time.NewTimer(s.watchSpeedWait())
		defer timer.Stop()
		timerC = timer.C
	}
	for {
		if err := ctx.Err(); err != nil {
			return SpeedList{}, err
		}
		s.speedViewMu.Lock()
		initialized := s.speedView.initialized
		fault := s.speedView.fault
		revision := s.speedView.revision
		nextExpiry := s.speedView.nextExpiry
		if !initialized {
			s.speedViewMu.Unlock()
			s.mu.Lock()
			s.expireSpeedsAtLocked(time.Now())
			s.publishSpeedStateLocked()
			s.mu.Unlock()
			continue
		}
		if fault {
			s.speedViewMu.Unlock()
			return SpeedList{}, errors.New("speed_state_unavailable")
		}
		now := time.Now()
		if !nextExpiry.IsZero() && !now.Before(nextExpiry) {
			s.speedViewMu.Unlock()
			s.mu.Lock()
			s.expireSpeedsAtLocked(now)
			s.publishSpeedStateLocked()
			s.mu.Unlock()
			continue
		}
		if after == nil || *after != revision {
			tests := cloneSpeedViews(s.speedView.tests)
			nodes := s.speedView.nodes
			hub := s.speedView.hub
			s.speedViewMu.Unlock()
			return SpeedList{
				Revision: revision,
				Tests:    tests,
				Channels: speedChannelsFromNodes(nodes, hub),
				Policy:   currentSpeedPolicy(),
			}, nil
		}
		if s.speedView.changed == nil {
			s.speedView.changed = make(chan struct{})
		}
		changed := s.speedView.changed
		s.speedViewMu.Unlock()

		var expireTimer *time.Timer
		var expireC <-chan time.Time
		if !nextExpiry.IsZero() {
			if delay := time.Until(nextExpiry); delay <= 0 {
				continue
			} else {
				expireTimer = time.NewTimer(delay)
				expireC = expireTimer.C
			}
		}
		select {
		case <-ctx.Done():
			if expireTimer != nil {
				expireTimer.Stop()
			}
			return SpeedList{}, ctx.Err()
		case <-changed:
			if expireTimer != nil {
				expireTimer.Stop()
			}
		case <-timerC:
			if expireTimer != nil {
				expireTimer.Stop()
			}
			after = nil
			timerC = nil
		case <-expireC:
		}
	}
}
func (s *Store) expireSpeedsLocked() {
	s.expireSpeedsAtLocked(time.Now())
}
func (s *Store) expireSpeedsAtLocked(now time.Time) {
	if s.speedFault {
		return
	}
	changed := false
	for _, r := range s.speedJobs {
		if r.Phase != "done" && r.Phase != "cleanup" && r.Phase != "client-cleanup" && !now.Before(r.View.StartedAt.Add(speedLease)) {
			r.View.State = "failed"
			r.View.Error = "lease_expired_cleanup_unconfirmed"
			r.Phase = "client-cleanup"
			changed = true
		}
	}
	if changed {
		_ = s.saveSpeedLocked()
	}
}
