package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// transportTestOperations preserves existing failure-recovery scenarios on
// the current gRPC wire protocol; authentication is covered by channel tests.
type transportTestOperations struct {
	pb.UnimplementedNodeOperationsServer
	exchange func(context.Context, exchange) (Desired, error)
	cancel   func(context.Context, TransportTail) (Desired, error)
	resume   func(context.Context, Observation) error
}

func (f *transportTestOperations) Exchange(ctx context.Context, doc *pb.NodeDocument) (*pb.NodeDocument, error) {
	var message exchange
	if err := nodeDocument(doc, &message, maxMessage); err != nil || f.exchange == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid exchange")
	}
	v, err := f.exchange(ctx, message)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "exchange not confirmed")
	}
	return nodeReply(v)
}
func (f *transportTestOperations) CancelTransport(ctx context.Context, doc *pb.NodeDocument) (*pb.NodeDocument, error) {
	var tail TransportTail
	if err := nodeDocument(doc, &tail, maxMessage); err != nil || f.cancel == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid cancellation")
	}
	v, err := f.cancel(ctx, tail)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "cancellation not confirmed")
	}
	return nodeReply(v)
}
func (f *transportTestOperations) ResumeTransport(ctx context.Context, doc *pb.NodeDocument) (*pb.NodeDocument, error) {
	var actual Observation
	if err := nodeDocument(doc, &actual, maxMessage); err != nil || f.resume == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid restoration")
	}
	if err := f.resume(ctx, actual); err != nil {
		return nil, status.Error(codes.Unavailable, "restoration not confirmed")
	}
	return nodeReply(struct{}{})
}
func transportTestClient(t *testing.T, service *transportTestOperations) *Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	pb.RegisterNodeOperationsServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Client{grpc: conn}
}

type transportDriverFixture struct {
	*driverFixture
	removed bool
	started time.Time
}

func (d *transportDriverFixture) Activate(ctx context.Context, desired Desired, previous *Desired) error {
	if err := d.driverFixture.Activate(ctx, desired, previous); err != nil {
		return err
	}
	d.started = time.Now().UTC().Truncate(time.Second)
	return nil
}

func (d *transportDriverFixture) verifyTransportFence(context.Context, Desired) error {
	if d.removed {
		return errors.New("fixture fence missing")
	}
	return nil
}
func (d *transportDriverFixture) removeTransportFence(context.Context, Desired) error {
	d.removed = true
	return nil
}

func (d *transportDriverFixture) traffic(_ context.Context, desired Desired) (*EntryTraffic, error) {
	now := time.Now().UTC()
	return quotaReceipt(desired, d.started, now, 7).Traffic, nil
}

func TestExpiredPreparationCancellationPreservesLedger(t *testing.T) {
	r, base := nativeFixture(t)
	driver := &transportDriverFixture{driverFixture: base}
	r.Driver = driver
	q, old, started := quotaFixture(t)
	q.TotalBytes = 1000000
	ctx := context.Background()
	if err := r.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	s := store(t)
	cert := strings.Repeat("a", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: old, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	tail := TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: quotaReceipt(old, started, time.Now().UTC(), 25).Traffic}
	if err := s.RecordTransportTail(ctx, cert, tail); err != nil {
		t.Fatal(err)
	}
	// Advance the sealed fixture into an expired state without waiting a minute.
	tail.Traffic = tail.Traffic.clone()
	tail.Traffic.SampledAt = time.Now().UTC().Add(-2 * time.Minute)
	n := s.nodes[cert]
	n.TransportTail = &tail
	n.EntryQuota.Raw = tail.Traffic.clone()
	n.EntryQuota.Forwarded.SampledAt = tail.Traffic.SampledAt
	s.nodes[cert] = n
	saved := transportPreparation{Binding: driver.Binding(), Desired: old, Tail: tail}
	raw, _ := json.Marshal(saved)
	if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
		t.Fatal(err)
	}
	base.running = false
	client := transportTestClient(t, &transportTestOperations{
		exchange: func(ctx context.Context, message exchange) (Desired, error) {
			return s.Exchange(ctx, cert, message.Receipt)
		},
		cancel: func(ctx context.Context, tail TransportTail) (Desired, error) {
			return s.TransportCancelIntent(ctx, cert, tail)
		},
		resume: func(ctx context.Context, actual Observation) error {
			if err := s.ResumeTransportPreparation(ctx, cert, actual); err != nil {
				return err
			}
			return errors.New("lost acknowledgement after commit")
		},
	})
	if err := r.CancelTransport(ctx, client); err != nil {
		t.Fatal(err)
	}
	if s.nodes[cert].EntryQuota.UsedBytes != q.UsedBytes+25+7 || !driver.removed || !base.running {
		t.Fatal("cancellation lost accounting or did not restore original worker")
	}
}

func TestTransportCompletionRetainsCheckpointOnLostAcknowledgement(t *testing.T) {
	r, base := nativeFixture(t)
	r.Driver = &transportDriverFixture{driverFixture: base}
	_, old, started := quotaFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	tail := quotaReceipt(old, started, time.Now().UTC(), 25)
	saved := transportPreparation{Binding: r.Driver.Binding(), Desired: old, Tail: TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: tail.Traffic}}
	raw, _ := json.Marshal(saved)
	if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	next.Entry.Revision++
	next.Entry.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}
	desired, err := NewEntryDesired(*next.Entry, *next.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	var failAck atomic.Bool
	failAck.Store(true)
	client := transportTestClient(t, &transportTestOperations{
		exchange: func(_ context.Context, message exchange) (Desired, error) {
			if message.Receipt != nil && failAck.Load() {
				return Desired{}, errors.New("lost acknowledgement")
			}
			return desired, nil
		},
	})
	if r.CompleteTransport(ctx, client) == nil {
		t.Fatal("lost acknowledgement reported success")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "transport-prepared.json")); err != nil {
		t.Fatal("checkpoint lost", err)
	}
	starts := base.starts
	failAck.Store(false)
	if err := r.CompleteTransport(ctx, client); err != nil {
		t.Fatal(err)
	}
	if base.starts != starts {
		t.Fatal("retry restarted the accounted generation")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "transport-prepared.json")); !os.IsNotExist(err) {
		t.Fatal("completed checkpoint still pending", err)
	}
}

func TestTransportFailureRestoresConfigurationOnlyWhileFenced(t *testing.T) {
	for _, scenario := range []string{"failed-health", "expired-tail", "missing-fence"} {
		t.Run(scenario, func(t *testing.T) {
			r, base := nativeFixture(t)
			driver := &transportDriverFixture{driverFixture: base}
			r.Driver = driver
			_, old, started := quotaFixture(t)
			ctx := context.Background()
			if err := r.Apply(ctx, old); err != nil {
				t.Fatal(err)
			}
			sampled := time.Now().UTC()
			if scenario == "expired-tail" {
				sampled = sampled.Add(-2 * time.Minute)
			}
			tail := quotaReceipt(old, started, sampled, 25)
			saved := transportPreparation{Binding: driver.Binding(), Desired: old, Tail: TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: tail.Traffic}}
			raw, _ := json.Marshal(saved)
			if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
				t.Fatal(err)
			}
			next := old.clone()
			next.Entry.Revision++
			next.Entry.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}
			desired, err := NewEntryDesired(*next.Entry, *next.EntryNetwork)
			if err != nil {
				t.Fatal(err)
			}
			client := transportTestClient(t, &transportTestOperations{
				exchange: func(context.Context, exchange) (Desired, error) { return desired, nil },
			})
			starts := base.starts
			if scenario == "failed-health" {
				base.failHealth = 1
			}
			if scenario == "missing-fence" {
				driver.removed = true
			}
			if r.CompleteTransport(ctx, client) == nil {
				t.Fatal("unsafe switch succeeded")
			}
			if scenario != "failed-health" && base.starts != starts {
				t.Fatal("aborted switch started worker")
			}
			if base.active.ConfigSHA256 != old.ConfigSHA256 {
				t.Fatal("old configuration not restored")
			}
			if scenario == "failed-health" && driver.removed {
				t.Fatal("failed activation released ingress")
			}
			if _, err := os.Stat(filepath.Join(r.Directory, "transport-prepared.json")); err != nil {
				t.Fatal("recovery checkpoint lost", err)
			}
		})
	}
}
