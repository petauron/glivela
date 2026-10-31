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
func (s *Store) saveSpeedLocked() error {
	if s.speedFault {
		return errors.New("speed_state_unavailable")
	}
	s.speedRevision++
	jobs := map[string]speedDiskRecord{}
	for id, r := range s.speedJobs {
		jobs[id] = speedDiskRecord{r.SubmittedBy, r.Request, r.View, r.Target, r.LandingCertificate, r.Source, r.Issued, r.Reports, r.Phase, r.ClientClean, r.Progress}
	}
	if err := writeControlState(s.speedStatePath(), speedState{1, s.speedRevision, jobs}); err != nil {
		s.speedFault = true
		return errors.New("speed_state_unavailable")
	}
	if s.speedChanged != nil {
		close(s.speedChanged)
	}
	s.speedChanged = make(chan struct{})
	if s.speedHub != nil {
		s.speedHub.wake()
	}
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

func (s *Store) speedChannelsLocked() []SpeedChannel {
	out := make([]SpeedChannel, 0, len(s.nodes))
	for certificate, node := range s.nodes {
		out = append(out, SpeedChannel{node.ID, s.speedHub != nil && s.speedHub.online(certificate)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type SpeedList struct {
	Channels []SpeedChannel `json:"channels"`
	Revision uint64         `json:"revision,string"`
	Tests    []SpeedView    `json:"tests"`
	Policy   SpeedPolicy    `json:"policy"`
}

// Event-driven HTTP wait fits the existing authenticated facade. New task
// revisions wake it immediately; there is no browser fixed-interval poll.
func (s *Store) WatchSpeeds(ctx context.Context, after *uint64) (SpeedList, error) {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		s.mu.Lock()
		if s.speedFault {
			s.mu.Unlock()
			return SpeedList{}, errors.New("speed_state_unavailable")
		}
		s.expireSpeedsLocked()
		if s.speedFault {
			s.mu.Unlock()
			return SpeedList{}, errors.New("speed_state_unavailable")
		}
		revision := s.speedRevision
		if s.speedChanged == nil {
			s.speedChanged = make(chan struct{})
		}
		changed := s.speedChanged
		if after == nil || *after != revision {
			v := s.speedViewsLocked()
			channels := s.speedChannelsLocked()
			s.mu.Unlock()
			return SpeedList{Revision: revision, Tests: v, Channels: channels, Policy: currentSpeedPolicy()}, nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return SpeedList{}, ctx.Err()
		case <-changed:
		case <-timer.C:
			after = nil
		}
	}
}
func (s *Store) expireSpeedsLocked() {
	changed := false
	for _, r := range s.speedJobs {
		if r.Phase != "done" && r.Phase != "cleanup" && r.Phase != "client-cleanup" && time.Since(r.View.StartedAt) > speedLease {
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
