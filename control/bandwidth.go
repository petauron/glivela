package control

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

func speedID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.String() == value
}

const speedLease = 4 * time.Minute
const speedDurationSeconds = 8
const speedWarmupSeconds = 1
const speedPort = 35260
const speedSSPort = 35261
const speedDownPort = 35262
const speedSSDownPort = 35263

type SpeedRequest struct {
	ID        string   `json:"id"`
	EntryID   string   `json:"entryId"`
	LandingID string   `json:"landingId"`
	Modes     []string `json:"modes"`
}
type SpeedSample struct {
	Mbps        float64 `json:"mbps"`
	Bytes       int64   `json:"bytes"`
	SentBytes   int64   `json:"sentBytes"`
	Seconds     float64 `json:"seconds"`
	Retransmits *uint64 `json:"retransmits,omitempty"`
}
type SpeedMeasurement struct {
	Upload        *SpeedSample `json:"upload"`
	Download      *SpeedSample `json:"download"`
	UploadError   string       `json:"uploadError,omitempty"`
	DownloadError string       `json:"downloadError,omitempty"`
	Error         string       `json:"error,omitempty"`
}
type SpeedPolicy struct {
	DurationSeconds   int    `json:"durationSeconds"`
	WarmupSeconds     int    `json:"warmupSeconds"`
	PerNodeBytes      uint64 `json:"perNodeBytes,omitempty"`
	PerDirectionBytes uint64 `json:"perDirectionBytes,omitempty"`
}

func currentSpeedPolicy() SpeedPolicy {
	return SpeedPolicy{DurationSeconds: speedDurationSeconds, WarmupSeconds: speedWarmupSeconds}
}

type SpeedPoint struct {
	Mode      string  `json:"mode"`
	Direction string  `json:"direction"`
	Sequence  uint32  `json:"sequence"`
	Mbps      float64 `json:"mbps"`
	Seconds   float64 `json:"seconds"`
}

type SpeedView struct {
	Progress         []SpeedProgress   `json:"progress,omitempty"`
	Phase            string            `json:"phase"`
	Modes            []string          `json:"modes"`
	ID               string            `json:"id"`
	EntryID          string            `json:"entryId"`
	LandingID        string            `json:"landingId"`
	State            string            `json:"state"`
	StartedAt        time.Time         `json:"startedAt"`
	FinishedAt       *time.Time        `json:"finishedAt,omitempty"`
	Direct           *SpeedMeasurement `json:"direct"`
	SS2022           *SpeedMeasurement `json:"ss2022"`
	Error            string            `json:"error,omitempty"`
	CleanupConfirmed bool              `json:"cleanupConfirmed"`
	EntryWireBytes   *uint64           `json:"entryWireBytes,omitempty"`
	LandingWireBytes *uint64           `json:"landingWireBytes,omitempty"`
	Policy           *SpeedPolicy      `json:"policy,omitempty"`
	Points           []SpeedPoint      `json:"points,omitempty"`
}
type speedRecord struct {
	SubmittedBy        string
	Progress           map[string]*SpeedProgress
	Request            SpeedRequest
	View               SpeedView
	Target             latencyTarget
	LandingCertificate string
	Source             string
	Password           string
	SSKey              string
	PrivateKey         string
	PublicKey          string
	Issued             map[string]bool
	Reports            map[string]SpeedReport
	Phase              string
	ClientClean        bool
}

// Assignments travel only on enrolled node mTLS, never in administrator results.
type SpeedAssignment struct {
	ID           string    `json:"id"`
	Role         string    `json:"role"`
	Revision     uint64    `json:"revision"`
	ConfigSHA256 string    `json:"configSha256"`
	EntryID      string    `json:"entryId"`
	LandingID    string    `json:"landingId"`
	Address      string    `json:"address"`
	Source       string    `json:"source"`
	Modes        []string  `json:"modes"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Password     string    `json:"password"`
	SSKey        string    `json:"ssKey"`
	PrivateKey   string    `json:"privateKey,omitempty"`
	PublicKey    string    `json:"publicKey"`
}
type SpeedReport struct {
	FinishedAt       time.Time         `json:"finishedAt,omitempty"`
	ID               string            `json:"id"`
	Role             string            `json:"role"`
	Direct           *SpeedMeasurement `json:"direct"`
	SS2022           *SpeedMeasurement `json:"ss2022"`
	Error            string            `json:"error,omitempty"`
	CleanupConfirmed bool              `json:"cleanupConfirmed"`
	WireBytes        *uint64           `json:"wireBytes,omitempty"`
}

func speedModes(modes []string) bool {
	if len(modes) < 1 || len(modes) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, m := range modes {
		if m != "direct" && m != "ss2022" || seen[m] {
			return false
		}
		seen[m] = true
	}
	return true
}
func (p SpeedAssignment) validate() error {
	if (p.Role == "cleanup" || p.Role == "client-cleanup") && speedID(p.ID) && time.Until(p.ExpiresAt) > 0 && time.Until(p.ExpiresAt) <= time.Minute {
		return nil
	}
	if !speedID(p.ID) || !glivela.ValidIdentifier(p.EntryID) || !glivela.ValidIdentifier(p.LandingID) || p.EntryID == p.LandingID || p.Revision == 0 || !glivela.ValidIdentity(p.ConfigSHA256) || !publicSpeedAddresses(p.Address, p.Source) || !speedModes(p.Modes) || time.Until(p.ExpiresAt) <= 0 || time.Until(p.ExpiresAt) > speedLease || !speedRole(p.Role) || len(p.Password) != 32 {
		return errors.New("invalid speed assignment")
	}
	key, err := base64.StdEncoding.DecodeString(p.SSKey)
	if err != nil || len(key) != 16 {
		return errors.New("invalid speed authentication")
	}
	return nil
}
func (s *Store) speedPairLocked(entryID, landingID string, requireFresh bool) (latencyTarget, string, string, error) {
	fail := errors.New("pair_unavailable")
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return latencyTarget{}, "", "", fail
	}
	if target, certificate, source, err := s.chainSpeedPairLocked(entryID, landingID, requireFresh); err == nil {
		return target, certificate, source, nil
	}
	enabled := false
	for _, a := range s.business.material.Plan.Accounts {
		if !a.Account.Plan.Enabled {
			continue
		}
		for _, g := range a.Grants {
			if g.Enabled && g.EntryID == entryID && (g.EgressID == landingID || g.IPv4EgressID == landingID) {
				enabled = true
			}
		}
	}
	t, ok := s.serverLatencyTargetLocked(entryID, landingID)
	now := time.Now()
	if !enabled || !ok || !glivela.PublicTransportIPv4(t.Address) || s.suspended(entryID, now) || s.suspended(landingID, now) || requireFresh && !s.latencyOnlineLocked(t, now) {
		return latencyTarget{}, "", "", fail
	}
	for cert, n := range s.nodes {
		if n.ID == landingID && n.Desired.Landing != nil && n.Desired.Landing.Transport.Protocol == "ss2022" && n.Desired.Landing.Transport.PublicAddress == t.Address {
			source, ok := n.RouteEntries[entryID]
			if !ok || source.CertificateID != t.Certificate {
				break
			}
			for _, p := range n.Desired.Landing.Sources {
				if p.Address == source.Address && glivela.PublicTransportIPv4(p.PublicAddress) {
					if !requireFresh {
						// A previously issued stage may reconnect with stale health, but
						// never against expired, revoked, or otherwise stale policy.
						projected, _, err := projectBusinessEntries(s.nodes, s.business.material, now)
						if err != nil || !reflect.DeepEqual(projected[t.Certificate].Desired, s.nodes[t.Certificate].Desired) || !reflect.DeepEqual(projected[cert].Desired, n.Desired) {
							return latencyTarget{}, "", "", fail
						}
					}
					return t, cert, p.PublicAddress, nil
				}
			}
		}
	}
	return latencyTarget{}, "", "", fail
}
func (s *Store) StartSpeed(request SpeedRequest, actor string) (SpeedView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.speedFault {
		return SpeedView{}, errors.New("speed_state_unavailable")
	}
	if !glivela.ValidIdentity(actor) || !speedID(request.ID) || !speedModes(request.Modes) {
		return SpeedView{}, errors.New("invalid_request")
	}
	if old := s.speedJobs[request.ID]; old != nil {
		if old.SubmittedBy != actor || !reflect.DeepEqual(old.Request, request) {
			return SpeedView{}, errors.New("request_identity_changed")
		}
		return old.View, nil
	}
	now := time.Now().UTC()
	for _, r := range s.speedJobs {
		if now.Before(r.View.StartedAt.Add(speedLease+15*time.Second)) && !r.View.CleanupConfirmed {
			return SpeedView{}, errors.New("test_busy_or_cleanup_pending")
		}
	}
	t, cert, source, err := s.speedPairLocked(request.EntryID, request.LandingID, true)
	if err != nil {
		return SpeedView{}, err
	}
	if s.speedHub == nil || !s.speedHub.online(t.Certificate) || !s.speedHub.online(cert) {
		return SpeedView{}, errors.New("control_disconnected")
	}
	if recent := s.latencies[latencyTargetKey(t)]; recent != nil && recent.Result != nil && recent.Result.LatencyMillis != nil && *recent.Result.LatencyMillis > 100 {
		return SpeedView{}, errors.New("latency_above_100ms")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return SpeedView{}, errors.New("authentication_unavailable")
	}
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		return SpeedView{}, err
	}
	sskey := base64.StdEncoding.EncodeToString(raw)
	if _, err = rand.Read(raw); err != nil {
		return SpeedView{}, err
	}
	password := hex.EncodeToString(raw)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return SpeedView{}, err
	}
	policy := currentSpeedPolicy()
	r := &speedRecord{SubmittedBy: actor, Request: request, View: SpeedView{ID: request.ID, EntryID: request.EntryID, LandingID: request.LandingID, Modes: request.Modes, State: "queued", StartedAt: now, Policy: &policy}, Target: t, LandingCertificate: cert, Source: source, Password: password, SSKey: sskey, PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})), Issued: map[string]bool{}, Reports: map[string]SpeedReport{}, Progress: map[string]*SpeedProgress{}, Phase: "receiver", ClientClean: true}
	if s.speedJobs == nil {
		s.speedJobs = map[string]*speedRecord{}
	}
	if len(s.speedJobs) >= 32 {
		var oldest *speedRecord
		for _, x := range s.speedJobs {
			if oldest == nil || x.View.StartedAt.Before(oldest.View.StartedAt) {
				oldest = x
			}
		}
		delete(s.speedJobs, oldest.Request.ID)
	}
	s.speedJobs[r.Request.ID] = r
	if err := s.saveSpeedLocked(); err != nil {
		return SpeedView{}, err
	}
	return r.View, nil
}
func (s *Store) Speeds() []SpeedView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.speedViewsLocked()
}
func (s *Store) speedViewsLocked() []SpeedView {
	out := []SpeedView{}
	for _, r := range s.speedJobs {

		v := r.View
		v.Points = append([]SpeedPoint(nil), r.View.Points...)
		v.Phase = r.Phase
		for _, role := range []string{"receiver", "client", "client-cleanup", "cleanup"} {
			if p := r.Progress[role]; p != nil {
				v.Progress = append(v.Progress, *p)
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}
func speedSampleError(s *SpeedSample) string {
	if s == nil || s.SentBytes <= 0 || s.Bytes <= 0 {
		return "iperf_result_bytes_invalid"
	}
	if math.IsNaN(s.Seconds) || math.IsInf(s.Seconds, 0) || s.Seconds < float64(speedDurationSeconds-1) || s.Seconds > 40 {
		return "iperf_result_duration_invalid"
	}
	if math.IsNaN(s.Mbps) || math.IsInf(s.Mbps, 0) || s.Mbps <= 0 || math.Abs(s.Mbps-float64(s.Bytes)*8/s.Seconds/1e6) > 0.01 {
		return "iperf_result_rate_invalid"
	}
	// Sender and receiver reset their counters independently after the warmup.
	// Bytes already in flight can make the receiver's count exceed the sender's.
	return ""
}

func validSpeedMeasurement(m *SpeedMeasurement) bool {
	if m == nil || len(m.Error) > 64 || len(m.UploadError) > 64 || len(m.DownloadError) > 64 {
		return false
	}
	for _, outcome := range []struct {
		sample *SpeedSample
		err    string
	}{{m.Upload, m.UploadError}, {m.Download, m.DownloadError}} {
		if outcome.sample != nil {
			if outcome.err != "" || speedSampleError(outcome.sample) != "" {
				return false
			}
		} else if outcome.err == "" && m.Error == "" {
			return false
		}
	}
	return true
}

func speedMeasurementFailed(m *SpeedMeasurement) bool {
	return m != nil && (m.Error != "" || m.UploadError != "" || m.DownloadError != "")
}
func (s *Store) SpeedExchange(ctx context.Context, certificate string, report *SpeedReport, session ...*speedStreamSession) (assignment *SpeedAssignment, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s.speedFault {
		return nil, errors.New("speed_state_unavailable")
	}
	if len(session) > 0 && !s.speedHub.current(certificate, session[0]) {
		return nil, errors.New("session_replaced")
	}
	node, ok := s.nodes[certificate]
	if !ok {
		return nil, errors.New("node_not_enrolled")
	}
	changed := false
	defer func() {
		if changed && resultErr == nil {
			if err := s.saveSpeedLocked(); err != nil {
				assignment = nil
				resultErr = err
			}
		}
	}()
	if report != nil {
		r := s.speedJobs[report.ID]
		if r == nil {
			return nil, errors.New("attempt_expired")
		}
		expected := r.Target.Certificate
		if report.Role == "receiver" || report.Role == "cleanup" {
			expected = r.LandingCertificate
		}
		if certificate != expected {
			return nil, errors.New("report_refused")
		}
		if previous, ok := r.Reports[report.Role]; ok {
			if reflect.DeepEqual(previous, *report) {
				return nil, nil
			}
			return nil, errors.New("result_already_received")
		}
		if certificate != expected || !r.Issued[report.Role] || len(report.Error) > 64 {
			return nil, errors.New("report_refused")
		}
		if report.Role != r.Phase {
			return nil, errors.New("superseded_phase")
		}
		if report.Role != "client" && (report.Direct != nil || report.SS2022 != nil) {
			return nil, errors.New("unexpected_measurement")
		}
		switch report.Role {
		case "receiver":
			if report.Error != "" {
				r.View.Error = report.Error
				r.Phase = "cleanup"
			} else {
				r.Phase = "client"
				r.View.State = "running"
			}
		case "client":
			selected := map[string]bool{}
			for _, mode := range r.Request.Modes {
				selected[mode] = true
			}
			if report.Direct != nil && !selected["direct"] || report.SS2022 != nil && !selected["ss2022"] {
				return nil, errors.New("unselected_result")
			}
			// Validate the complete report before changing any visible result.
			for _, mode := range r.Request.Modes {
				if mode == "direct" && !validSpeedMeasurement(report.Direct) || mode == "ss2022" && !validSpeedMeasurement(report.SS2022) {
					return nil, errors.New("invalid_result")
				}
			}
			r.ClientClean = report.CleanupConfirmed
			if report.Error != "" {
				r.View.Error = report.Error
			}
			r.View.EntryWireBytes = report.WireBytes
			if selected["direct"] {
				r.View.Direct = report.Direct
			}
			if selected["ss2022"] {
				r.View.SS2022 = report.SS2022
			}
			if time.Since(r.View.StartedAt) > speedLease {
				r.View.Error = "test_lease_expired"
			}

			if !report.CleanupConfirmed {
				r.View.Error = "client_cleanup_unconfirmed"
			}
			r.Phase = "cleanup"
			r.View.State = "cleaning"
		case "client-cleanup":
			r.ClientClean = report.CleanupConfirmed && report.Error == ""
			r.View.EntryWireBytes = report.WireBytes
			r.Phase = "cleanup"
		case "cleanup":
			r.View.LandingWireBytes = report.WireBytes
			r.View.CleanupConfirmed = r.ClientClean && report.CleanupConfirmed && report.Error == ""
			stamp := time.Now().UTC()
			r.View.FinishedAt = &stamp
			r.View.State = "completed"
			if r.View.Error != "" || !r.View.CleanupConfirmed || speedMeasurementFailed(r.View.Direct) || speedMeasurementFailed(r.View.SS2022) {
				r.View.State = "failed"
			}
			if !r.View.CleanupConfirmed {
				r.View.Error = "receiver_cleanup_unconfirmed"
			}
			r.Phase = "done"
			r.Password = ""
			r.SSKey = ""
			r.PrivateKey = ""
			r.PublicKey = ""
		default:
			return nil, errors.New("invalid_phase")
		}
		changed = true
		if r.Progress == nil {
			r.Progress = map[string]*SpeedProgress{}
		}
		progress := r.Progress[report.Role]
		if progress == nil {
			progress = &SpeedProgress{Role: report.Role}
			r.Progress[report.Role] = progress
		}
		now := time.Now().UTC()
		progress.ConfirmedAt = &now
		if !report.FinishedAt.IsZero() && report.FinishedAt.Before(now.Add(time.Minute)) {
			at := report.FinishedAt
			progress.FinishedAt = &at
		}
		r.Reports[report.Role] = *report
		return nil, nil
	}
	for _, r := range s.speedJobs {
		if r.Phase == "done" || r.Phase != "cleanup" && r.Phase != "client-cleanup" && time.Since(r.View.StartedAt) > speedLease {
			continue
		}
		owner := r.Target.Certificate
		if r.Phase != "client" && r.Phase != "client-cleanup" {
			owner = r.LandingCertificate
		}
		if owner != certificate {
			continue
		}
		if r.Phase != "cleanup" && r.Phase != "client-cleanup" {
			reissued := r.Issued[r.Phase]
			t, c, source, err := s.speedPairLocked(r.Request.EntryID, r.Request.LandingID, !reissued)
			// A manual suspension or resume after the task began invalidates its
			// authority even if the currently effective suspension has expired.
			changedBarrier := s.recoveryBarrier(r.Request.EntryID).After(r.View.StartedAt) || s.recoveryBarrier(r.Request.LandingID).After(r.View.StartedAt)
			if err != nil || changedBarrier || t != r.Target || c != r.LandingCertificate || source != r.Source {
				r.View.Error = "pair_identity_or_configuration_changed"
				r.Phase = "client-cleanup"
				r.View.State = "cleaning"
				changed = true
				continue
			}
		}
		p := SpeedAssignment{ID: r.Request.ID, Role: r.Phase, EntryID: r.Request.EntryID, LandingID: r.Request.LandingID, Revision: node.Desired.Revision, ConfigSHA256: node.Desired.ConfigSHA256, Address: r.Target.Address, Source: r.Source, Modes: r.Request.Modes, ExpiresAt: r.View.StartedAt.Add(speedLease), Password: r.Password, SSKey: r.SSKey, PublicKey: r.PublicKey}
		if p.Role == "cleanup" || p.Role == "client-cleanup" {
			p.ExpiresAt = time.Now().UTC().Add(30 * time.Second)
		}
		if p.Role == "receiver" {
			p.PrivateKey = r.PrivateKey
		}
		if !r.Issued[r.Phase] {
			changed = true
		}
		r.Issued[r.Phase] = true
		if r.Phase == "client" {
			r.ClientClean = false
		}
		return &p, nil
	}
	return nil, nil
}
func speedPasswordHash(password string) string {
	h := sha256.Sum256([]byte("{speed}" + password))
	return hex.EncodeToString(h[:])
}
