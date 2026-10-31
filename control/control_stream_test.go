package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func controlFixture(t *testing.T) (*Store, *Client, *Client, string) {
	t.Helper()
	_, ca, key := identity(t, nil, nil, false)
	server, _, _ := identity(t, ca, key, true)
	node, cert, _ := identity(t, ca, key, false)
	outsider, _, _ := identity(t, ca, key, false)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s := store(t)
	if err := s.Put(Node{ID: "node-one", CertificateID: CertificateID(cert), Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	app, err := NewServer("127.0.0.1:0", s, server, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the installed panel-access startup path as well as plain TLS.
	_, panelCA, panelSigner := identity(t, nil, nil, false)
	panelServer, panelLeaf, _ := identity(t, panelCA, panelSigner, true)
	panelLeaf.DNSNames = []string{"panel.glivela.internal"}
	der, err := x509.CreateCertificate(rand.Reader, panelLeaf, panelCA, &panelServer.PrivateKey.(*ecdsa.PrivateKey).PublicKey, panelSigner)
	if err != nil {
		t.Fatal(err)
	}
	panelClient, _, _ := identity(t, panelCA, panelSigner, false)
	private, err := x509.MarshalPKCS8PrivateKey(panelServer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	asPEM := func(kind string, data []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}))
	}
	bundle, err := json.Marshal(map[string]string{"ca": asPEM("CERTIFICATE", panelCA.Raw), "certificate": asPEM("CERTIFICATE", der), "key": asPEM("PRIVATE KEY", private), "clientCertificate": asPEM("CERTIFICATE", panelClient.Certificate[0])})
	if err != nil {
		t.Fatal(err)
	}
	panelFile := filepath.Join(filepath.Dir(s.path), "panel.json")
	if err = os.WriteFile(panelFile, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	if err = ConfigurePanelAccess(app, s, nil, panelFile); err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(app.Handler)
	listener.EnableHTTP2 = true
	listener.TLS = app.TLSConfig.Clone()
	listener.Config.HTTP2 = app.HTTP2
	listener.Config.ReadTimeout = 200 * time.Millisecond
	listener.Config.WriteTimeout = 200 * time.Millisecond
	listener.StartTLS()
	t.Cleanup(listener.Close)
	c, err := NewClient(listener.URL, node, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	bad, err := NewClient(listener.URL, outsider, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bad.Close)
	return s, c, bad, CertificateID(cert)
}
func openControl(t *testing.T, ctx context.Context, c *Client) grpc.BidiStreamingClient[pb.NodeFrame, pb.ControllerFrame] {
	t.Helper()
	stream, err := pb.NewNodeControlClient(c.grpc).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Hello{Hello: &pb.Hello{Version: controlVersion, Capabilities: []string{speedCapability}}}}); err != nil {
		t.Fatal(err)
	}
	v, err := stream.Recv()
	if err != nil || v.GetWelcome() == nil {
		t.Fatalf("welcome: %v", err)
	}
	return stream
}
func cleanupTask(id, cert string) *speedRecord {
	return &speedRecord{Request: SpeedRequest{ID: id, EntryID: "entry-one", LandingID: "node-one", Modes: []string{"direct"}}, View: SpeedView{ID: id, State: "cleaning", StartedAt: time.Now().UTC()}, LandingCertificate: cert, Issued: map[string]bool{}, Reports: map[string]SpeedReport{}, Progress: map[string]*SpeedProgress{}, Phase: "cleanup", ClientClean: true}
}
func TestControlStreamMTLSIsolationPushAndLostReceipt(t *testing.T) {
	s, c, bad, cert := controlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	unknown, err := pb.NewNodeControlClient(bad.grpc).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = unknown.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Hello{Hello: &pb.Hello{Version: controlVersion, Capabilities: []string{speedCapability}}}})
	if _, err = unknown.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unenrolled identity accepted: %v", err)
	}
	firstCtx, stopFirst := context.WithCancel(ctx)
	first := openControl(t, firstCtx, c)
	id := uuid.NewString()
	s.mu.Lock()
	s.speedJobs = map[string]*speedRecord{id: cleanupTask(id, cert)}
	if err = s.saveSpeedLocked(); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	assignment, err := first.Recv()
	if err != nil || assignment.GetAssignment() == nil || assignment.GetAssignment().Id != id {
		t.Fatalf("push: %v", err)
	}
	if err = first.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Result{Result: &pb.Result{Id: id, Role: "cleanup", Direct: &pb.Measurement{Upload: &pb.Sample{Mbps: math.NaN()}}}}}); err != nil {
		t.Fatal(err)
	}
	refused, err := first.Recv()
	if err != nil || refused.GetReceipt().GetAccepted() {
		t.Fatal("malformed result accepted")
	}
	// Survive beyond the ordinary HTTP request deadline: the stream is not a
	// 200 ms JSON request. This checks the actual HTTP/2 TLS handler path.
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	result := &pb.Result{Id: id, Role: "cleanup", CleanupConfirmed: true, FinishedAtUnixNano: time.Now().UnixNano()}
	if err = first.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Result{Result: result}}); err != nil {
		t.Fatal(err)
	}
	receipt, err := first.Recv()
	if err != nil || !receipt.GetReceipt().GetAccepted() {
		t.Fatalf("result: %v / %v", err, receipt)
	}
	// Pretend the node did not observe the acknowledgement and reconnect. Old
	// progress + the same result must be accepted without another execution.
	stopFirst()
	second := openControl(t, ctx, c)
	if err = second.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Progress{Progress: &pb.Progress{Id: id, Role: "cleanup", Stage: "received"}}}); err != nil {
		t.Fatal(err)
	}
	if err = second.Send(&pb.NodeFrame{Body: &pb.NodeFrame_Result{Result: result}}); err != nil {
		t.Fatal(err)
	}
	replay, err := second.Recv()
	if err != nil || !replay.GetReceipt().GetAccepted() {
		t.Fatalf("receipt replay failed: %v / %v", err, replay)
	}
	s.mu.Lock()
	job := s.speedJobs[id]
	if job.Phase != "done" || job.View.State != "completed" || len(job.Reports) != 1 {
		t.Fatal("terminal receipt changed")
	}
	s.mu.Unlock()
	loaded, err := OpenStore(s.path)
	if err != nil || loaded.speedJobs[id].View.State != "completed" {
		t.Fatalf("terminal not durable: %v", err)
	}
}
func TestSpeedNodeDuplicateAndInterruptedRecovery(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := SpeedRunner{Directory: dir}
	engine, err := newSpeedEngine(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var count atomic.Int32
	executed := make(chan struct{}, 1)
	engine.execute = func(_ context.Context, a SpeedAssignment) SpeedReport {
		count.Add(1)
		executed <- struct{}{}
		return SpeedReport{ID: a.ID, Role: a.Role, CleanupConfirmed: true}
	}
	done := make(chan struct{})
	go func() { defer close(done); engine.run(ctx) }()
	defer func() { cancel(); <-done }()
	a := SpeedAssignment{ID: uuid.NewString(), Role: "cleanup", ExpiresAt: time.Now().Add(25 * time.Second)}
	if err = engine.accept(a); err != nil {
		t.Fatal(err)
	}
	select {
	case <-executed:
	case <-time.After(time.Second):
		t.Fatal("not executed")
	}
	for {
		engine.mu.Lock()
		finished := engine.journal.Records[speedKey(a.ID, a.Role)].Result != nil
		engine.mu.Unlock()
		if finished {
			break
		}
		select {
		case <-engine.changed:
		case <-time.After(time.Second):
			t.Fatal("no durable result")
		}
	}
	if err = engine.accept(a); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatal("duplicate transfer")
	}
	if err = engine.ack(&pb.Receipt{Id: a.ID, Role: a.Role, Accepted: true}); err != nil {
		t.Fatal(err)
	}
	next := SpeedAssignment{ID: uuid.NewString(), Role: "cleanup", ExpiresAt: time.Now().Add(25 * time.Second)}
	// Keep this record received but unexecuted, modelling a crash at the fence.
	engine.mu.Lock()
	engine.journal.Records[speedKey(next.ID, next.Role)] = &speedNodeRecord{ID: next.ID, Role: next.Role, Digest: speedAssignmentDigest(next), Stage: "received", UpdatedAt: time.Now().UTC()}
	err = engine.saveLocked()
	engine.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := newSpeedEngine(r)
	if err != nil {
		t.Fatal(err)
	}
	rec := recovered.journal.Records[speedKey(next.ID, next.Role)]
	if rec.Result == nil || rec.Result.Error != "interrupted_execution" || rec.WasRunning {
		t.Fatal("crash recovery fabricated execution")
	}
	if err = recovered.accept(next); err != nil {
		t.Fatal(err)
	}
	if len(recovered.queue) != 0 {
		t.Fatal("interrupted work re-executed")
	}
}
func TestSpeedPersistenceExcludesTemporaryCredentialsAndWakesWaiter(t *testing.T) {
	s := store(t)
	_, ca, key := identity(t, nil, nil, false)
	_, cert, _ := identity(t, ca, key, false)
	fingerprint := CertificateID(cert)
	if err := s.Put(Node{ID: "node-one", CertificateID: fingerprint, Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	job := cleanupTask(id, fingerprint)
	job.Phase = "receiver"
	job.Password = "temporary-password-marker"
	job.PrivateKey = "temporary-key-marker"
	job.SSKey = "temporary-ss-marker"
	s.mu.Lock()
	s.speedJobs = map[string]*speedRecord{id: job}
	err := s.saveSpeedLocked()
	revision := s.speedRevision
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.speedStatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{job.Password, job.PrivateKey, job.SSKey} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("temporary secret persisted")
		}
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.speedJobs[id].Phase != "client-cleanup" || loaded.speedJobs[id].View.Error != "controller_restarted" {
		t.Fatal("restart did not schedule safe cleanup")
	}
	response := make(chan SpeedList, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { v, _ := s.WatchSpeeds(ctx, &revision); response <- v }()
	s.mu.Lock()
	job.View.Error = "fixture-change"
	err = s.saveSpeedLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-response:
		if v.Revision <= revision || v.Tests[0].Error != "fixture-change" {
			t.Fatal("stale event")
		}
	case <-ctx.Done():
		t.Fatal("event wait did not wake")
	}
}

func TestSpeedRunnerReconnectDoesNotRestartInFlightExecution(t *testing.T) {
	s, client, _, cert := controlFixture(t)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := SpeedRunner{Client: client, Directory: directory}
	engine, err := newSpeedEngine(runner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	started, release := make(chan struct{}, 1), make(chan struct{})
	var executions atomic.Int32
	engine.execute = func(ctx context.Context, a SpeedAssignment) SpeedReport {
		executions.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return SpeedReport{ID: a.ID, Role: a.Role, CleanupConfirmed: true}
	}
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); engine.run(ctx) }()
	defer func() { cancel(); <-workerDone }()
	id := uuid.NewString()
	s.mu.Lock()
	s.speedJobs = map[string]*speedRecord{id: cleanupTask(id, cert)}
	err = s.saveSpeedLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- runner.connect(ctx, engine) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("assignment not executed")
	}
	s.speedHub.mu.Lock()
	session := s.speedHub.nodes[cert]
	session.cancel()
	s.speedHub.mu.Unlock()
	select {
	case <-firstDone:
	case <-ctx.Done():
		t.Fatal("disconnected stream stayed blocked")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- runner.connect(ctx, engine) }()
	defer func() { cancel(); <-secondDone }()
	close(release)
	for {
		engine.mu.Lock()
		record := engine.journal.Records[speedKey(id, "cleanup")]
		acked := record != nil && record.Acked
		engine.mu.Unlock()
		if acked {
			break
		}
		select {
		case <-engine.changed:
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("receipt not recovered")
		}
	}
	if executions.Load() != 1 {
		t.Fatalf("executed %d times", executions.Load())
	}
	s.mu.Lock()
	terminal := s.speedJobs[id].View.State
	s.mu.Unlock()
	if terminal != "completed" {
		t.Fatal(terminal)
	}
}
