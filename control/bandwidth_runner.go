package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	glivela "github.com/petauron/glivela"
	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Execution lives independently of the transport. A stream reconnect replays
// durable receipts; it never starts another transfer for the same assignment.
type SpeedRunner struct {
	Client                            *Client
	Directory, CoreBinary, CoreSHA256 string
	IperfBinary, IperfSHA256          string
}
type speedNodeRecord struct {
	ID, Role, Digest, Stage string
	WasRunning              bool
	Modes                   []string
	Points                  []SpeedPoint
	Result                  *SpeedReport
	Acked                   bool
	UpdatedAt               time.Time
}
type speedNodeJournal struct {
	Version int
	Records map[string]*speedNodeRecord
}
type speedEngine struct {
	mu        sync.Mutex
	directory string
	journal   speedNodeJournal
	queue     chan SpeedAssignment
	changed   chan struct{}
	fatal     error
	client    *Client
	session   *speedSession
	execute   func(context.Context, SpeedAssignment) SpeedReport
}

func speedKey(id, role string) string { return id + "/" + role }
func speedAssignmentDigest(a SpeedAssignment) string {
	if a.Role == "cleanup" || a.Role == "client-cleanup" {
		return speedKey(a.ID, a.Role)
	}
	raw, _ := json.Marshal(a)
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}
func (e *speedEngine) saveLocked() error {
	if e.fatal != nil {
		return e.fatal
	}
	if err := writeControlState(filepath.Join(e.directory, "control-speed-receipts.json"), e.journal); err != nil {
		e.fatal = errors.New("speed receipt persistence failed")
		return e.fatal
	}
	select {
	case e.changed <- struct{}{}:
	default:
	}
	return nil
}
func newSpeedEngine(r SpeedRunner) (*speedEngine, error) {
	e := &speedEngine{directory: r.Directory, client: r.Client, session: newSpeedSession(r.Directory, r.CoreBinary, r.CoreSHA256, r.IperfBinary, r.IperfSHA256), queue: make(chan SpeedAssignment, 1), changed: make(chan struct{}, 1), journal: speedNodeJournal{Version: 1, Records: map[string]*speedNodeRecord{}}}
	if err := e.session.recover(); err != nil {
		return nil, err
	}
	e.execute = e.session.execute
	e.session.setProgress(e.addSpeedPoint)
	err := readControlState(filepath.Join(e.directory, "control-speed-receipts.json"), &e.journal)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if e.journal.Version != 1 || len(e.journal.Records) > 128 || e.journal.Records == nil {
		return nil, errors.New("invalid speed receipts")
	}
	changed := false
	for key, v := range e.journal.Records {
		if v == nil || !speedID(v.ID) || !speedRole(v.Role) || key != speedKey(v.ID, v.Role) || v.Digest == "" {
			return nil, errors.New("invalid speed receipt identity")
		}
		if v.Result == nil {
			report := speedFailure(v.ID, v.Role, v.Modes, "interrupted_execution", true)
			v.Result = &report
			v.Stage = "finished"
			v.UpdatedAt = time.Now().UTC()
			changed = true
		}
	}
	if changed {
		if err := e.saveLocked(); err != nil {
			return nil, err
		}
	}
	return e, nil
}
func speedFailure(id, role string, modes []string, reason string, clean bool) SpeedReport {
	r := SpeedReport{ID: id, Role: role, Error: reason, CleanupConfirmed: clean, FinishedAt: time.Now().UTC()}
	if role == "client" {
		for _, mode := range modes {
			if mode == "direct" {
				r.Direct = &SpeedMeasurement{Error: reason}
			}
			if mode == "ss2022" {
				r.SS2022 = &SpeedMeasurement{Error: reason}
			}
		}
	}
	return r
}
func (e *speedEngine) accept(a SpeedAssignment) error {
	if err := a.validate(); err != nil {
		return err
	}
	key := speedKey(a.ID, a.Role)
	digest := speedAssignmentDigest(a)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fatal != nil {
		return e.fatal
	}
	if old := e.journal.Records[key]; old != nil {
		if old.Digest != digest {
			return errors.New("assignment identity changed")
		}
		select {
		case e.changed <- struct{}{}:
		default:
		}
		return nil
	}
	for _, v := range e.journal.Records {
		if v.Result == nil {
			return errors.New("node execution busy")
		}
	}
	if len(e.journal.Records) >= 128 {
		var oldest string
		for k, v := range e.journal.Records {
			if v.Acked && (oldest == "" || v.UpdatedAt.Before(e.journal.Records[oldest].UpdatedAt)) {
				oldest = k
			}
		}
		if oldest == "" {
			return errors.New("receipt capacity exhausted")
		}
		delete(e.journal.Records, oldest)
	}
	e.journal.Records[key] = &speedNodeRecord{ID: a.ID, Role: a.Role, Digest: digest, Stage: "received", Modes: append([]string(nil), a.Modes...), UpdatedAt: time.Now().UTC()}
	if err := e.saveLocked(); err != nil {
		return err
	}
	select {
	case e.queue <- a:
		return nil
	default:
		return errors.New("execution queue full")
	}
}
func (e *speedEngine) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-e.queue:
			key := speedKey(a.ID, a.Role)
			e.mu.Lock()
			record := e.journal.Records[key]
			record.Stage = "running"
			record.WasRunning = true
			record.UpdatedAt = time.Now().UTC()
			err := e.saveLocked()
			e.mu.Unlock()
			if err != nil {
				return
			}
			var report SpeedReport
			if a.Role == "cleanup" || a.Role == "client-cleanup" {
				report = e.execute(ctx, a)
			} else {
				verify, stop := context.WithTimeout(ctx, 20*time.Second)
				desired, verifyErr := e.client.currentDesired(verify)
				stop()
				if verifyErr != nil || desired.Validate() != nil || desired.Revision != a.Revision || desired.ConfigSHA256 != a.ConfigSHA256 || !speedLocalPair(desired, a) {
					report = speedFailure(a.ID, a.Role, a.Modes, "configuration_or_identity_changed", e.session.close() == nil)
				} else {
					report = e.execute(ctx, a)
				}
			}
			if report.Role == "client" && report.Error != "" {
				for _, mode := range a.Modes {
					if mode == "direct" && report.Direct == nil {
						report.Direct = &SpeedMeasurement{Error: report.Error}
					}
					if mode == "ss2022" && report.SS2022 == nil {
						report.SS2022 = &SpeedMeasurement{Error: report.Error}
					}
				}
			}
			report.FinishedAt = time.Now().UTC()
			e.mu.Lock()
			record.Result = &report
			record.Stage = "finished"
			record.UpdatedAt = time.Now().UTC()
			err = e.saveLocked()
			e.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}
func (e *speedEngine) frames() ([]*pb.NodeFrame, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fatal != nil {
		return nil, e.fatal
	}
	out := []*pb.NodeFrame{}
	for _, v := range e.journal.Records {
		if v.Acked {
			continue
		}
		// Preserve real receipt order even if execution completed before the writer
		// was scheduled. Progress values are not inferred from a successful send.
		out = append(out, &pb.NodeFrame{Body: &pb.NodeFrame_Progress{Progress: &pb.Progress{Id: v.ID, Role: v.Role, Stage: "received"}}})
		if v.WasRunning {
			out = append(out, &pb.NodeFrame{Body: &pb.NodeFrame_Progress{Progress: &pb.Progress{Id: v.ID, Role: v.Role, Stage: "running"}}})
		}
		for _, point := range v.Points {
			out = append(out, &pb.NodeFrame{Body: &pb.NodeFrame_Progress{Progress: &pb.Progress{Id: v.ID, Role: v.Role, Stage: "sample", Mode: point.Mode, Direction: point.Direction, Sequence: point.Sequence, Mbps: point.Mbps, Seconds: point.Seconds}}})
		}
		if v.Result != nil {
			out = append(out, &pb.NodeFrame{Body: &pb.NodeFrame_Result{Result: reportProto(*v.Result)}})
		}
	}
	return out, nil
}
func (e *speedEngine) addSpeedPoint(id string, point SpeedPoint) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := e.journal.Records[speedKey(id, "client")]
	if v == nil || v.Result != nil || len(v.Points) >= 44 {
		return
	}
	v.Points = append(v.Points, point)
	v.UpdatedAt = time.Now().UTC()
	_ = e.saveLocked()
}
func (e *speedEngine) ack(r *pb.Receipt) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r == nil {
		return errors.New("missing receipt")
	}
	v := e.journal.Records[speedKey(r.Id, r.Role)]
	if v == nil || v.Result == nil {
		return errors.New("unexpected receipt")
	}
	// Rejected obsolete phases stay visibly rejected at the controller; dropping
	// the local outbound receipt cannot authorize another execution.
	if v.Acked {
		return nil
	}
	if !r.Accepted && r.Error != "attempt_expired" && r.Error != "superseded_phase" {
		return errors.New("result not confirmed")
	}
	v.Acked = true
	v.UpdatedAt = time.Now().UTC()
	return e.saveLocked()
}
func (r SpeedRunner) Run(ctx context.Context) {
	engine, err := newSpeedEngine(r)
	if err != nil {
		log.Print("Glivela speed recovery unconfirmed; diagnostics disabled")
		return
	}
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); engine.run(workerCtx) }()
	defer func() { stop(); <-done; _ = engine.session.close() }()
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err = r.connect(ctx, engine)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("Glivela gRPC control stream unavailable (%s); existing proxy unchanged", status.Code(err))
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
func (r SpeedRunner) connect(parent context.Context, e *speedEngine) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// Bound connection establishment as well as Welcome; Send can wait for TLS.
	establish := time.AfterFunc(10*time.Second, cancel)
	defer establish.Stop()
	stream, err := pb.NewNodeControlClient(r.Client.grpc).Connect(ctx)
	if err != nil {
		return err
	}
	if err = stream.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Hello{Hello: &pb.Hello{Version: controlVersion, Capabilities: []string{speedCapability}}}}); err != nil {
		return err
	}
	incoming := make(chan *pb.ControllerFrame, 4)
	failed := make(chan error, 1)
	go func() {
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
				case failed <- errors.New("control frame too large"):
				default:
				}
				return
			}
			select {
			case incoming <- v:
			case <-ctx.Done():
				return
			}
		}
	}()
	handshake := time.NewTimer(10 * time.Second)
	defer handshake.Stop()
	select {
	case frame := <-incoming:
		if frame.GetWelcome() == nil || frame.GetWelcome().Version != controlVersion {
			return errors.New("unsupported control version")
		}
	case err := <-failed:
		return err
	case <-handshake.C:
		return errors.New("control handshake timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
	establish.Stop()
	send := func() error {
		frames, err := e.frames()
		if err != nil {
			return err
		}
		for _, frame := range frames {
			if proto.Size(frame) > controlMessageLimit {
				return errors.New("control frame too large")
			}
			done := make(chan error, 1)
			go func() { done <- stream.Send(frame) }()
			timer := time.NewTimer(10 * time.Second)
			select {
			case err = <-done:
				timer.Stop()
			case <-timer.C:
				return errors.New("control send timeout")
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err = send(); err != nil {
		return err
	}
	retry := time.NewTicker(10 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			return err
		case <-e.changed:
			if err = send(); err != nil {
				return err
			}
		case <-retry.C:
			if err = send(); err != nil {
				return err
			}
		case frame := <-incoming:
			switch v := frame.Body.(type) {
			case *pb.ControllerFrame_Assignment:
				if v.Assignment == nil {
					return errors.New("missing assignment")
				}
				if err = e.accept(assignmentFromProto(v.Assignment)); err != nil {
					return err
				}
			case *pb.ControllerFrame_Receipt:
				if err = e.ack(v.Receipt); err != nil {
					return err
				}
			default:
				return errors.New("unexpected controller frame")
			}
		}
	}
}
func speedLocalPair(d Desired, p SpeedAssignment) bool {
	if p.Role == "cleanup" || p.Role == "client-cleanup" {
		return true
	}
	if p.Role == "receiver" && d.Landing != nil {
		for _, listener := range d.Landing.ClientListeners {
			address := d.Landing.Transport.PublicAddress
			if listener.Transport == "ipv6-ss2022" {
				address = listener.Address
			}
			if address == p.Address && listener.Source == p.Source {
				return true
			}
		}
	}
	if p.Role == "receiver" && d.Landing != nil && d.Landing.Transport.PublicAddress == p.Address && d.Landing.Transport.Protocol == "ss2022" {
		for _, source := range d.Landing.Sources {
			if source.PublicAddress == p.Source {
				return true
			}
		}
	}
	if p.Role == "client" && d.Entry != nil {
		if d.EntryNetwork != nil {
			for _, peer := range d.EntryNetwork.SpeedPeers {
				if peer.LandingID == p.LandingID && peer.Address == p.Address && peer.Source == p.Source {
					for _, credential := range d.Entry.Credentials {
						c := credential.Credential
						if c.Enabled && c.Kind == glivela.NativeCredential && c.EntryID == p.EntryID && c.AccountID == peer.AccountID {
							return true
						}
					}
				}
			}
		}
		for _, peer := range d.Entry.Peers {
			if peer.EgressID == p.LandingID && peer.Transport.PublicAddress == p.Address && peer.Transport.Protocol == "ss2022" {
				return true
			}
		}
	}
	return false
}

var errSpeedUnsupported = errors.New("linux_required")
