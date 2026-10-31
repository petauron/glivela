package control

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const controlVersion = 1
const speedCapability = "link-speed.v7"
const controlMessageLimit = 64 << 10

type speedStreamSession struct {
	wake   chan struct{}
	cancel context.CancelFunc
}
type speedHub struct {
	mu    sync.Mutex
	nodes map[string]*speedStreamSession
}

func newSpeedHub() *speedHub { return &speedHub{nodes: map[string]*speedStreamSession{}} }
func (h *speedHub) online(cert string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nodes[cert] != nil
}
func (h *speedHub) current(cert string, s *speedStreamSession) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nodes[cert] == s
}
func (h *speedHub) replace(cert string, s *speedStreamSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.nodes[cert]; old != nil {
		old.cancel()
	}
	h.nodes[cert] = s
}
func (h *speedHub) remove(cert string, s *speedStreamSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nodes[cert] == s {
		delete(h.nodes, cert)
	}
}
func (h *speedHub) wake() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.nodes {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

type nodeControlServer struct {
	pb.UnimplementedNodeControlServer
	store *Store
}

func newControlHTTP(store *Store, next http.Handler) http.Handler {
	server := grpc.NewServer(grpc.MaxRecvMsgSize(maxMessage+4096), grpc.MaxSendMsgSize(maxMessage+4096), grpc.MaxConcurrentStreams(8))
	pb.RegisterNodeControlServer(server, &nodeControlServer{store: store})
	pb.RegisterNodeOperationsServer(server, &nodeOperationsServer{store: store})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/glivela.control.v1.NodeControl/") || strings.HasPrefix(r.URL.Path, "/glivela.control.v1.NodeOperations/") {
			if r.ProtoMajor != 2 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				http.Error(w, "HTTP/2 gRPC required", 426)
				return
			}
			// Keep the existing HTTP request limits for all other endpoints. Streams
			// have their own bounded receive/handshake/send deadlines below.
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Time{}) != nil || controller.SetWriteDeadline(time.Time{}) != nil {
				http.Error(w, "stream deadlines unavailable", 503)
				return
			}
			server.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func receiveFrame(stream grpc.BidiStreamingServer[pb.NodeFrame, pb.ControllerFrame], ctx context.Context, out chan<- *pb.NodeFrame, failed chan<- error) {
	for {
		v, err := stream.Recv()
		if err != nil {
			select {
			case failed <- err:
			default:
			}
			return
		}
		if proto.Size(v) > controlMessageLimit {
			select {
			case failed <- status.Error(codes.ResourceExhausted, "control frame too large"):
			default:
			}
			return
		}
		select {
		case out <- v:
		case <-ctx.Done():
			return
		}
	}
}
func sendFrame(ctx context.Context, stream grpc.BidiStreamingServer[pb.NodeFrame, pb.ControllerFrame], v *pb.ControllerFrame) error {
	if proto.Size(v) > controlMessageLimit {
		return status.Error(codes.ResourceExhausted, "control frame too large")
	}
	done := make(chan error, 1)
	go func() { done <- stream.Send(v) }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return status.Error(codes.DeadlineExceeded, "slow control receiver")
	}
}
func (s *nodeControlServer) Connect(stream grpc.BidiStreamingServer[pb.NodeFrame, pb.ControllerFrame]) error {
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "mTLS required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "mTLS required")
	}
	cert := CertificateID(tlsInfo.State.PeerCertificates[0])
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	frames := make(chan *pb.NodeFrame, 4)
	failed := make(chan error, 1)
	go receiveFrame(stream, ctx, frames, failed)
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	select {
	case v := <-frames:
		hello := v.GetHello()
		if hello == nil || hello.Version != controlVersion || len(hello.Capabilities) > 8 || !slices.Contains(hello.Capabilities, speedCapability) {
			return status.Error(codes.Unimplemented, "control capability unavailable")
		}
	case err := <-failed:
		return err
	case <-timeout.C:
		return status.Error(codes.DeadlineExceeded, "control hello timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
	session := &speedStreamSession{wake: make(chan struct{}, 1), cancel: cancel}
	s.store.mu.Lock()
	node, enrolled := s.store.nodes[cert]
	enrolled = enrolled && !s.store.entryRetiredLocked(node.ID)
	if s.store.speedHub == nil {
		s.store.speedHub = newSpeedHub()
	}
	hub := s.store.speedHub
	if enrolled {
		hub.replace(cert, session)
	}
	s.store.mu.Unlock()
	if !enrolled {
		return status.Error(codes.PermissionDenied, "node not enrolled")
	}
	defer hub.remove(cert, session)
	if err := sendFrame(ctx, stream, &pb.ControllerFrame{Body: &pb.ControllerFrame_Welcome{Welcome: &pb.Welcome{Version: controlVersion, SessionId: uuid.NewString()}}}); err != nil {
		return err
	}
	sent := map[string]bool{}
	check := time.NewTicker(30 * time.Second)
	defer check.Stop()
	for {
		s.store.mu.Lock()
		node, valid := s.store.nodes[cert]
		valid = valid && !s.store.entryRetiredLocked(node.ID)
		s.store.expireSpeedsLocked()
		s.store.mu.Unlock()
		if !valid || time.Now().After(tlsInfo.State.PeerCertificates[0].NotAfter) || !hub.current(cert, session) {
			return status.Error(codes.PermissionDenied, "control identity changed")
		}
		a, err := s.store.SpeedExchange(ctx, cert, nil, session)
		if err != nil {
			return status.Error(codes.Unavailable, "task state unavailable")
		}
		if a != nil {
			key := a.ID + "/" + a.Role
			if !sent[key] {
				if err := sendFrame(ctx, stream, &pb.ControllerFrame{Body: &pb.ControllerFrame_Assignment{Assignment: assignmentProto(*a)}}); err != nil {
					return err
				}
				sent[key] = true
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-session.wake:
		case <-check.C:
		case frame := <-frames:
			if !hub.current(cert, session) {
				return status.Error(codes.Aborted, "session replaced")
			}
			switch v := frame.Body.(type) {
			case *pb.NodeFrame_Progress:
				if s.store.recordSpeedProgress(cert, session, v.Progress) != nil {
					return status.Error(codes.PermissionDenied, "progress refused")
				}
			case *pb.NodeFrame_Result:
				if v.Result == nil {
					return status.Error(codes.InvalidArgument, "missing result")
				}
				result := reportFromProto(v.Result)
				_, err := s.store.SpeedExchange(ctx, cert, &result, session)
				receipt := &pb.Receipt{Id: result.ID, Role: result.Role, Accepted: err == nil}
				if err != nil {
					receipt.Error = "result_not_accepted"
					if err.Error() == "attempt_expired" || err.Error() == "superseded_phase" {
						receipt.Error = err.Error()
					}
				}
				if err := sendFrame(ctx, stream, &pb.ControllerFrame{Body: &pb.ControllerFrame_Receipt{Receipt: receipt}}); err != nil {
					return err
				}
			default:
				return status.Error(codes.InvalidArgument, "unexpected control frame")
			}
		}
	}
}
func (s *Store) recordSpeedProgress(cert string, session *speedStreamSession, p *pb.Progress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil || s.speedFault || !s.speedHub.current(cert, session) {
		return errors.New("session unavailable")
	}
	if !speedID(p.Id) || !speedRole(p.Role) || p.Stage != "received" && p.Stage != "running" && p.Stage != "sample" {
		return errors.New("invalid progress")
	}
	r := s.speedJobs[p.Id]
	if r == nil {
		// A retained node receipt can outlive the bounded controller history.
		// Ignore its progress so its final result receives attempt_expired.
		return nil
	}
	if !r.Issued[p.Role] {
		return errors.New("unknown task")
	}
	owner := r.Target.Certificate
	if p.Role == "receiver" || p.Role == "cleanup" {
		owner = r.LandingCertificate
	}
	if owner != cert {
		return errors.New("progress refused")
	}
	if r.Phase != p.Role {
		return nil
	}
	if p.Stage == "sample" {
		if p.Role != "client" || !slices.Contains(r.Request.Modes, p.Mode) || p.Direction != "upload" && p.Direction != "download" || p.Sequence > 10 || math.IsNaN(p.Mbps) || math.IsInf(p.Mbps, 0) || p.Mbps < 0 || math.IsNaN(p.Seconds) || math.IsInf(p.Seconds, 0) || (p.Sequence == 0 && (p.Mbps != 0 || p.Seconds != 0)) || (p.Sequence > 0 && (p.Seconds <= 0 || p.Seconds > 35)) {
			return errors.New("invalid speed sample")
		}
		point := SpeedPoint{Mode: p.Mode, Direction: p.Direction, Sequence: p.Sequence, Mbps: p.Mbps, Seconds: p.Seconds}
		for _, old := range r.View.Points {
			if old.Mode == point.Mode && old.Direction == point.Direction && old.Sequence == point.Sequence {
				if old == point {
					return nil
				}
				return errors.New("conflicting speed sample")
			}
		}
		if len(r.View.Points) >= 44 {
			return errors.New("too many speed samples")
		}
		r.View.Points = append(r.View.Points, point)
		return s.saveSpeedLocked()
	}
	if r.Progress == nil {
		r.Progress = map[string]*SpeedProgress{}
	}
	progress := r.Progress[p.Role]
	if progress == nil {
		progress = &SpeedProgress{Role: p.Role}
		r.Progress[p.Role] = progress
	}
	now := time.Now().UTC()
	if p.Stage == "received" {
		if progress.ReceivedAt != nil {
			return nil
		}
		progress.ReceivedAt = &now
	} else {
		if progress.ReceivedAt == nil {
			return errors.New("task not received")
		}
		if progress.RunningAt != nil {
			return nil
		}
		progress.RunningAt = &now
	}
	return s.saveSpeedLocked()
}
func assignmentProto(v SpeedAssignment) *pb.Assignment {
	return &pb.Assignment{Id: v.ID, Role: v.Role, Revision: v.Revision, ConfigSha256: v.ConfigSHA256, EntryId: v.EntryID, LandingId: v.LandingID, Address: v.Address, Source: v.Source, Modes: v.Modes, ExpiresAtUnixNano: v.ExpiresAt.UnixNano(), Password: v.Password, SsKey: v.SSKey, PrivateKey: v.PrivateKey, PublicKey: v.PublicKey}
}
func assignmentFromProto(v *pb.Assignment) SpeedAssignment {
	return SpeedAssignment{ID: v.Id, Role: v.Role, Revision: v.Revision, ConfigSHA256: v.ConfigSha256, EntryID: v.EntryId, LandingID: v.LandingId, Address: v.Address, Source: v.Source, Modes: v.Modes, ExpiresAt: time.Unix(0, v.ExpiresAtUnixNano).UTC(), Password: v.Password, SSKey: v.SsKey, PrivateKey: v.PrivateKey, PublicKey: v.PublicKey}
}
func sampleProto(v *SpeedSample) *pb.Sample {
	if v == nil {
		return nil
	}
	return &pb.Sample{Mbps: v.Mbps, Bytes: v.Bytes, SentBytes: v.SentBytes, Seconds: v.Seconds, Retransmits: v.Retransmits}
}
func sampleFromProto(v *pb.Sample) *SpeedSample {
	if v == nil {
		return nil
	}
	return &SpeedSample{Mbps: v.Mbps, Bytes: v.Bytes, SentBytes: v.SentBytes, Seconds: v.Seconds, Retransmits: v.Retransmits}
}
func measurementProto(v *SpeedMeasurement) *pb.Measurement {
	if v == nil {
		return nil
	}
	return &pb.Measurement{Upload: sampleProto(v.Upload), Download: sampleProto(v.Download), Error: v.Error, UploadError: v.UploadError, DownloadError: v.DownloadError}
}
func measurementFromProto(v *pb.Measurement) *SpeedMeasurement {
	if v == nil {
		return nil
	}
	return &SpeedMeasurement{Upload: sampleFromProto(v.Upload), Download: sampleFromProto(v.Download), Error: v.Error, UploadError: v.UploadError, DownloadError: v.DownloadError}
}
func reportProto(v SpeedReport) *pb.Result {
	return &pb.Result{Id: v.ID, Role: v.Role, Direct: measurementProto(v.Direct), Ss2022: measurementProto(v.SS2022), Error: v.Error, CleanupConfirmed: v.CleanupConfirmed, WireBytes: v.WireBytes, FinishedAtUnixNano: v.FinishedAt.UnixNano()}
}
func reportFromProto(v *pb.Result) SpeedReport {
	return SpeedReport{ID: v.Id, Role: v.Role, Direct: measurementFromProto(v.Direct), SS2022: measurementFromProto(v.Ss2022), Error: v.Error, CleanupConfirmed: v.CleanupConfirmed, WireBytes: v.WireBytes, FinishedAt: time.Unix(0, v.FinishedAtUnixNano).UTC()}
}
