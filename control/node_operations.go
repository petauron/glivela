package control

// Node operations use a fixed set of gRPC methods. JSON documents reuse the
// existing strict domain validators; no generic host or HTTP dispatch exists.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"time"

	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	nodeSignalDesired uint32 = 1 << iota
	nodeSignalRoute
	nodeSignalLatency
	nodeSignalNetwork
	nodeSignalQuality
	nodeSignalAll = nodeSignalDesired | nodeSignalRoute | nodeSignalLatency | nodeSignalNetwork | nodeSignalQuality
)

type nodeEventSession struct {
	wake    chan struct{}
	cancel  context.CancelFunc
	pending uint32
}
type nodeEventHub struct {
	mu    sync.Mutex
	nodes map[string]*nodeEventSession
}

func newNodeEventHub() *nodeEventHub { return &nodeEventHub{nodes: map[string]*nodeEventSession{}} }
func (h *nodeEventHub) replace(cert string, session *nodeEventSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.nodes[cert]; old != nil {
		old.cancel()
	}
	h.nodes[cert] = session
}
func (h *nodeEventHub) remove(cert string, session *nodeEventSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nodes[cert] == session {
		delete(h.nodes, cert)
	}
}
func (h *nodeEventHub) wake(cert string, mask uint32) {
	if h == nil || mask == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.nodes[cert]; s != nil {
		s.pending |= mask
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}
func (h *nodeEventHub) take(cert string, session *nodeEventSession) (uint32, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nodes[cert] != session {
		return 0, false
	}
	value := session.pending
	session.pending = 0
	return value, true
}
func nodePeer(ctx context.Context) (string, *x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil, status.Error(codes.Unauthenticated, "mTLS required")
	}
	t, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(t.State.VerifiedChains) == 0 || len(t.State.PeerCertificates) == 0 {
		return "", nil, status.Error(codes.Unauthenticated, "mTLS required")
	}
	leaf := t.State.PeerCertificates[0]
	if time.Now().After(leaf.NotAfter) {
		return "", nil, status.Error(codes.Unauthenticated, "identity expired")
	}
	return CertificateID(leaf), leaf, nil
}
func (s *Store) nodeWatchAllowed(cert string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[cert]; ok && !s.entryRetiredLocked(n.ID) {
		return true
	}
	// Verifier-only identities may receive only their existing assigned checks.
	for _, n := range s.nodes {
		for _, entry := range n.RouteEntries {
			if entry.CertificateID == cert {
				return true
			}
		}
		for _, check := range n.Checks {
			if check.CertificateID == cert {
				return true
			}
		}
	}
	return false
}

type nodeOperationsServer struct {
	pb.UnimplementedNodeOperationsServer
	store *Store
}

func (s *nodeOperationsServer) peer(ctx context.Context) (string, *x509.Certificate, error) {
	cert, leaf, err := nodePeer(ctx)
	if err != nil {
		return "", nil, err
	}
	if !s.store.nodeWatchAllowed(cert) {
		return "", nil, status.Error(codes.PermissionDenied, "node not enrolled")
	}
	return cert, leaf, nil
}

func nodeDocument(in *pb.NodeDocument, value any, limit int) error {
	if in == nil || len(in.Json) == 0 || len(in.Json) > limit || decode(bytes.NewReader(in.Json), value) != nil {
		return status.Error(codes.InvalidArgument, "invalid node document")
	}
	return nil
}
func nodeReply(value any) (*pb.NodeDocument, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxMessage {
		return nil, status.Error(codes.ResourceExhausted, "node response unavailable")
	}
	return &pb.NodeDocument{Json: raw}, nil
}
func nodeRefused(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(codes.FailedPrecondition, "node operation not confirmed")
}
func (s *nodeOperationsServer) Exchange(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request exchange
	if err = nodeDocument(in, &request, maxMessage); err != nil {
		return nil, err
	}
	desired, err := s.store.Exchange(ctx, cert, request.Receipt)
	if err != nil || desired.Validate() != nil {
		return nil, status.Error(codes.FailedPrecondition, "desired state unavailable")
	}
	return nodeReply(desired)
}
func (s *nodeOperationsServer) CurrentDesired(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request struct{}
	if err = nodeDocument(in, &request, 4096); err != nil {
		return nil, err
	}
	desired, err := s.store.currentDesired(ctx, cert)
	if err != nil || desired.Validate() != nil {
		return nil, status.Error(codes.FailedPrecondition, "desired state unavailable")
	}
	return nodeReply(desired)
}
func (s *nodeOperationsServer) NetworkOptimization(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request struct {
		Report *NetworkReport `json:"report"`
	}
	if err = nodeDocument(in, &request, 16<<10); err != nil {
		return nil, err
	}
	command, err := s.store.exchangeNetwork(cert, request.Report)
	if err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(struct {
		Command *NetworkCommand `json:"command"`
	}{command})
}
func (s *nodeOperationsServer) IPQuality(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request qualityMessage
	if err = nodeDocument(in, &request, 128<<10); err != nil || request.Assignment != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid quality report")
	}
	a, err := s.store.qualityExchangeState(cert, request.Report)
	if err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(qualityMessage{Assignment: a})
}
func (s *nodeOperationsServer) RouteLatency(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request latencyExchange
	if err = nodeDocument(in, &request, 4096); err != nil {
		return nil, err
	}
	p, err := s.store.LatencyExchange(ctx, cert, request.Report)
	if err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(latencyAssignment{Probe: p})
}
func (s *nodeOperationsServer) RouteChecks(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request routeExchange
	if err = nodeDocument(in, &request, 16<<10); err != nil {
		return nil, err
	}
	checks, err := s.store.RouteExchange(ctx, cert, request.Report)
	if err != nil {
		return nil, nodeRefused(err)
	}
	if checks == nil {
		checks = []RouteProbe{}
	}
	return nodeReply(routeAssignments{Checks: checks})
}
func (s *nodeOperationsServer) LandingAcceptance(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var request landingAcceptanceRequest
	if err = nodeDocument(in, &request, 4096); err != nil {
		return nil, err
	}
	v, err := s.store.ownLandingAcceptance(cert, request)
	if err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(v)
}
func (s *nodeOperationsServer) RecordTransportTail(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var tail TransportTail
	if err = nodeDocument(in, &tail, maxMessage); err != nil {
		return nil, err
	}
	if err = s.store.RecordTransportTail(ctx, cert, tail); err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(struct{}{})
}
func (s *nodeOperationsServer) CancelTransport(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var tail TransportTail
	if err = nodeDocument(in, &tail, maxMessage); err != nil {
		return nil, err
	}
	desired, err := s.store.TransportCancelIntent(ctx, cert, tail)
	if err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(desired)
}
func (s *nodeOperationsServer) ResumeTransport(ctx context.Context, in *pb.NodeDocument) (*pb.NodeDocument, error) {
	cert, _, err := s.peer(ctx)
	if err != nil {
		return nil, err
	}
	var actual Observation
	if err = nodeDocument(in, &actual, maxMessage); err != nil {
		return nil, err
	}
	if err = s.store.ResumeTransportPreparation(ctx, cert, actual); err != nil {
		return nil, nodeRefused(err)
	}
	return nodeReply(struct{}{})
}
func (s *nodeOperationsServer) Watch(in *pb.NodeWatchRequest, stream grpc.ServerStreamingServer[pb.NodeSignal]) error {
	if in == nil || in.Version != controlVersion {
		return status.Error(codes.Unimplemented, "unsupported node events")
	}
	cert, leaf, err := s.peer(stream.Context())
	if err != nil {
		return err
	}
	if !s.store.nodeWatchAllowed(cert) {
		return status.Error(codes.PermissionDenied, "node not enrolled")
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	session := &nodeEventSession{wake: make(chan struct{}, 1), cancel: cancel, pending: nodeSignalAll}
	hub := s.store.nodeEvents
	if hub == nil {
		return status.Error(codes.Unavailable, "node events unavailable")
	}
	hub.replace(cert, session)
	defer hub.remove(cert, session)
	session.wake <- struct{}{}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(leaf.NotAfter) || !s.store.nodeWatchAllowed(cert) {
				return status.Error(codes.PermissionDenied, "node identity changed")
			}
		case <-session.wake:
			mask, ok := hub.take(cert, session)
			if !ok {
				return status.Error(codes.Aborted, "session replaced")
			}
			if mask == 0 {
				continue
			}
			done := make(chan error, 1)
			go func() { done <- stream.Send(&pb.NodeSignal{Mask: mask}) }()
			timer := time.NewTimer(10 * time.Second)
			select {
			case err = <-done:
				timer.Stop()
				if err != nil {
					return err
				}
			case <-timer.C:
				return status.Error(codes.DeadlineExceeded, "slow node event receiver")
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
	}
}

type nodeUnary func(context.Context, *pb.NodeDocument, ...grpc.CallOption) (*pb.NodeDocument, error)

func (c *Client) nodeCall(ctx context.Context, method nodeUnary, request, response any, limit, responseLimit int) error {
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > limit {
		return errors.New("control: invalid node request")
	}
	reply, err := method(ctx, &pb.NodeDocument{Json: raw})
	if err != nil || reply == nil || len(reply.Json) > responseLimit {
		return errors.New("control: node operation unavailable")
	}
	if decode(bytes.NewReader(reply.Json), response) != nil {
		return errors.New("control: invalid node response")
	}
	return nil
}
func (c *Client) nodeSignal(mask uint32) chan struct{} {
	switch mask {
	case nodeSignalDesired:
		return c.desiredWake
	case nodeSignalRoute:
		return c.routeWake
	case nodeSignalLatency:
		return c.latencyWake
	case nodeSignalNetwork:
		return c.networkWake
	case nodeSignalQuality:
		return c.qualityWake
	}
	return nil
}
func (c *Client) signalNodes(mask uint32) {
	for _, m := range []uint32{nodeSignalDesired, nodeSignalRoute, nodeSignalLatency, nodeSignalNetwork, nodeSignalQuality} {
		if mask&m != 0 {
			if ch := c.nodeSignal(m); ch != nil {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}
func (c *Client) RunNodeUpdates(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		stream, err := pb.NewNodeOperationsClient(c.grpc).Watch(ctx, &pb.NodeWatchRequest{Version: controlVersion})
		if err == nil {
			for ctx.Err() == nil {
				signal, e := stream.Recv()
				if e != nil {
					err = e
					break
				}
				if signal.Mask & ^uint32(nodeSignalAll) != 0 {
					err = errors.New("unknown node signal")
					break
				}
				c.signalNodes(signal.Mask)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, 30*time.Second)
	}
}
