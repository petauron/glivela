package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

// This exercises submission, both independently enrolled streams, progress,
// durable receipt and terminal query together. Only the byte-transfer work is
// synthetic; the actual executor is checked separately in the isolated lab.
func TestSpeedHTTPToGRPCCompleteTask(t *testing.T) { runSpeedHTTPToGRPC(t, false, false) }

func TestSpeedHTTPToGRPCReconnectDuringTransfer(t *testing.T) { runSpeedHTTPToGRPC(t, true, false) }

func TestSpeedHTTPToGRPCReconnectAfterStaleHeartbeat(t *testing.T) { runSpeedHTTPToGRPC(t, true, true) }

func runSpeedHTTPToGRPC(t *testing.T, disconnect, staleHeartbeat bool) {
	t.Helper()
	s, original, _, oldLanding := subscriptionFixture(t, true)
	landingPlan := *s.nodes[oldLanding].Desired.Landing
	transport := glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw==", PublicAddress: "11.177.0.2"}
	landingPlan.Transport = transport
	landingPlan.Sources[0].PublicAddress = "11.177.0.1"
	desiredLanding, err := NewDesired(landingPlan)
	if err != nil {
		t.Fatal(err)
	}
	entryPlan := *original.Entry
	entryPlan.Peers[0].Transport = transport
	desiredEntry, err := NewEntryDesired(entryPlan, *original.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}

	_, ca, caKey := identity(t, nil, nil, false)
	serverCert, _, _ := identity(t, ca, caKey, true)
	entryTLS, entryLeaf, _ := identity(t, ca, caKey, false)
	landingTLS, landingLeaf, _ := identity(t, ca, caKey, false)
	adminTLS, adminLeaf, _ := identity(t, ca, caKey, false)
	entryCert, landingCert := CertificateID(entryLeaf), CertificateID(landingLeaf)
	s.mu.Lock()
	s.nodes = map[string]Node{}
	s.mu.Unlock()
	if err = s.Put(Node{ID: "entry-example", CertificateID: entryCert, Desired: desiredEntry}); err != nil {
		t.Fatal(err)
	}
	if err = s.Put(Node{ID: "landing-example", CertificateID: landingCert, Desired: desiredLanding, RouteEntries: map[string]RouteEntry{"entry-example": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	desiredEntry = s.nodes[entryCert].Desired.clone()
	desiredLanding = s.nodes[landingCert].Desired.clone()
	s.mu.Unlock()
	reportRuntime(t, s, entryCert, desiredEntry)
	reportRuntime(t, s, landingCert, desiredLanding)
	s.mu.Lock()
	beforeEntry, beforeLanding := s.nodes[entryCert], s.nodes[landingCert]
	s.mu.Unlock()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	app, err := NewServer("127.0.0.1:0", s, serverCert, roots, []string{CertificateID(adminLeaf)})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(app.Handler)
	listener.EnableHTTP2 = true
	listener.TLS = app.TLSConfig.Clone()
	listener.Config.HTTP2 = app.HTTP2
	listener.StartTLS()
	defer listener.Close()
	entryEndpoint, dropEntry := listener.URL, func() {}
	if disconnect {
		entryEndpoint, dropEntry = controlTCPRelay(t, listener.URL)
	}
	entryClient, err := NewClient(entryEndpoint, entryTLS, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer entryClient.Close()
	landingClient, err := NewClient(listener.URL, landingTLS, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer landingClient.Close()
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{adminTLS}}}}
	defer httpClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	started, resume := make(chan struct{}), make(chan struct{})
	connectionErrors := make(chan error, 16)
	runs := map[string]int{}
	startWorker := func(client *Client, role string) {
		runner := SpeedRunner{Client: client, Directory: filepath.Clean(t.TempDir())}
		engine, e := newSpeedEngine(runner)
		if e != nil {
			t.Fatal(e)
		}
		engine.execute = func(_ context.Context, a SpeedAssignment) SpeedReport {
			mu.Lock()
			runs[role+"/"+a.Role]++
			mu.Unlock()
			if disconnect && role == "entry" && a.Role == "client" {
				close(started)
				select {
				case <-resume:
				case <-ctx.Done():
					return SpeedReport{ID: a.ID, Role: a.Role, Error: "test_canceled"}
				}
			}
			report := SpeedReport{ID: a.ID, Role: a.Role}
			if a.Role == "client" {
				sample := func() *SpeedSample {
					return &SpeedSample{Mbps: 40, Bytes: 40000000, SentBytes: 40000000, Seconds: 8}
				}
				report.Direct = &SpeedMeasurement{Upload: sample(), Download: sample()}
				report.SS2022 = &SpeedMeasurement{Upload: sample(), Download: sample()}
				report.CleanupConfirmed = true
			}
			if a.Role == "cleanup" || a.Role == "client-cleanup" {
				report.CleanupConfirmed = true
			}
			return report
		}
		workers.Add(2)
		go func() { defer workers.Done(); engine.run(ctx) }()
		firstCtx := ctx
		go func() {
			defer workers.Done()
			current := firstCtx
			for ctx.Err() == nil {
				err := runner.connect(current, engine)
				if ctx.Err() != nil {
					return
				}
				if role == "entry" {
					select {
					case connectionErrors <- err:
					default:
					}
				}
				current = ctx
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}()
	}
	startWorker(entryClient, "entry")
	startWorker(landingClient, "landing")
	for !s.speedHub.online(entryCert) || !s.speedHub.online(landingCert) {
		select {
		case <-ctx.Done():
			t.Fatal("streams did not connect")
		case <-time.After(10 * time.Millisecond):
		}
	}
	id := uuid.NewString()
	payload, _ := json.Marshal(map[string]any{"start": SpeedRequest{ID: id, EntryID: "entry-example", LandingID: "landing-example", Modes: []string{"direct", "ss2022"}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, listener.URL+"/v1/admin/link-speeds", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var first SpeedList
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("submission HTTP %d", response.StatusCode)
	}
	if err = json.NewDecoder(response.Body).Decode(&first); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if disconnect {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("client transfer did not start")
		}
		s.speedHub.mu.Lock()
		previous := s.speedHub.nodes[entryCert]
		s.speedHub.mu.Unlock()
		if staleHeartbeat {
			s.mu.Lock()
			entry := s.nodes[entryCert]
			entry.ReportedAt = time.Now().Add(-2 * time.Minute)
			s.nodes[entryCert] = entry
			beforeEntry = entry
			s.mu.Unlock()
		}
		dropEntry()
		select {
		case <-connectionErrors:
		case <-ctx.Done():
			t.Fatal("stream did not disconnect")
		}
		for {
			s.speedHub.mu.Lock()
			current := s.speedHub.nodes[entryCert]
			s.speedHub.mu.Unlock()
			if current != nil && current != previous {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("stream did not reconnect")
			case <-time.After(10 * time.Millisecond):
			}
		}
		close(resume)
	}
	revision := first.Revision
	final := first
	for {
		if len(final.Tests) == 1 {
			if final.Tests[0].State == "completed" {
				break
			}
			if final.Tests[0].State == "failed" {
				t.Fatalf("task failed: %+v", final.Tests[0])
			}
		}
		final, err = s.WatchSpeeds(ctx, &revision)
		if err != nil {
			mu.Lock()
			lastRuns := make(map[string]int, len(runs))
			for role, count := range runs {
				lastRuns[role] = count
			}
			mu.Unlock()
			var lastError error
			select {
			case lastError = <-connectionErrors:
			default:
			}
			t.Fatalf("task stalled: %v; snapshot=%+v; runs=%v; connection error=%v", err, s.Speeds(), lastRuns, lastError)
		}
		revision = final.Revision
	}
	result := final.Tests[0]
	if result.ID != id || !result.CleanupConfirmed || !validSpeedMeasurement(result.Direct) || !validSpeedMeasurement(result.SS2022) || len(result.Progress) != 3 {
		t.Fatalf("incomplete result: %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 3 || runs["landing/receiver"] != 1 || runs["entry/client"] != 1 || runs["landing/cleanup"] != 1 {
		t.Fatalf("wrong or duplicate execution: %v", runs)
	}
	s.mu.Lock()
	record := s.speedJobs[id]
	savedActor := record.SubmittedBy
	s.mu.Unlock()
	s.mu.Lock()
	afterEntry, afterLanding := s.nodes[entryCert], s.nodes[landingCert]
	s.mu.Unlock()
	if !reflect.DeepEqual(beforeEntry.Receipt, afterEntry.Receipt) || !reflect.DeepEqual(beforeLanding.Receipt, afterLanding.Receipt) || beforeEntry.ReportedAt != afterEntry.ReportedAt || beforeLanding.ReportedAt != afterLanding.ReportedAt || beforeEntry.EntryHealthBarrierAt != afterEntry.EntryHealthBarrierAt {
		t.Fatal("speed verification changed node health observations")
	}
	if savedActor != CertificateID(adminLeaf) {
		t.Fatal("authenticated submitter was not retained")
	}
	reopened, err := OpenStore(s.path)
	if err != nil || reopened.speedJobs[id].View.State != "completed" {
		t.Fatalf("terminal result not durable: %v", err)
	}
}

// A diagnostic read uses the enrolled node identity without submitting an
// empty observation, modifying health, or accepting stale business policy.
func TestCurrentDesiredReadOnlyAndPolicy(t *testing.T) {
	s, desired, certificate, _ := subscriptionFixture(t, true)
	reportRuntime(t, s, certificate, desired)
	beforeDisk, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	beforeNode := s.nodes[certificate]
	s.mu.Unlock()
	got, err := s.currentDesired(context.Background(), certificate)
	if err != nil || !reflect.DeepEqual(got, beforeNode.Desired) {
		t.Fatalf("current policy: %v", err)
	}
	if _, err = s.currentDesired(context.Background(), "not-enrolled"); err == nil {
		t.Fatal("unenrolled node accepted")
	}
	s.mu.Lock()
	ownership := s.business.material.Ownership
	s.business.material.Ownership = nil
	s.mu.Unlock()
	if _, err = s.currentDesired(context.Background(), certificate); err == nil {
		t.Fatal("unowned business accepted")
	}
	s.mu.Lock()
	s.business.material.Ownership = ownership
	s.business.faulted = true
	s.mu.Unlock()
	if _, err = s.currentDesired(context.Background(), certificate); err == nil {
		t.Fatal("faulted business accepted")
	}
	s.mu.Lock()
	s.business.faulted = false
	s.mu.Unlock()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.currentDesired(canceled, certificate); err == nil {
		t.Fatal("canceled request accepted")
	}
	s.mu.Lock()
	// Expiry requires a new credential projection; the read must fail closed
	// without persisting that projection or erasing the existing observation.
	s.business.material.Plan.Accounts[0].Account.Plan.ExpiryTime = time.Now().Add(-time.Minute).UnixMilli()
	s.mu.Unlock()
	if _, err = s.currentDesired(context.Background(), certificate); err == nil {
		t.Fatal("stale expiry policy accepted")
	}
	s.mu.Lock()
	afterNode := s.nodes[certificate]
	s.mu.Unlock()
	afterDisk, err := os.ReadFile(s.path)
	if err != nil || !bytes.Equal(beforeDisk, afterDisk) || !reflect.DeepEqual(beforeNode, afterNode) {
		t.Fatal("diagnostic read mutated stored node or health")
	}
}

func TestCurrentDesiredEndpointRejectsUnownedAndUnknownNode(t *testing.T) {
	s, node, outsider, _ := controlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	beforeDisk, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.currentDesired(ctx); err == nil {
		t.Fatal("unowned business accepted for enrolled node")
	}
	if _, err = outsider.currentDesired(ctx); err == nil {
		t.Fatal("unknown certificate accepted")
	}
	endpoint := node.endpoint[:len(node.endpoint)-len("/v1/exchange")] + "/v1/current-desired"
	for _, tc := range []struct{ url, body string }{
		{endpoint, `{"unexpected":true}`}, {endpoint + "?unexpected=1", `{}`},
	} {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, tc.url, bytes.NewBufferString(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := node.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("invalid diagnostic request accepted")
		}
	}
	afterDisk, err := os.ReadFile(s.path)
	if err != nil || !bytes.Equal(beforeDisk, afterDisk) {
		t.Fatal("diagnostic request wrote node state")
	}
}

// Close actual TCP connections (including HTTP/2), not just a child stream,
// while keeping the controller and node execution alive.
func controlTCPRelay(t *testing.T, endpoint string) (string, func()) {
	t.Helper()
	remote, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	pairs := map[net.Conn]net.Conn{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				outgoing, err := net.DialTimeout("tcp", remote.Host, 2*time.Second)
				if err != nil {
					_ = incoming.Close()
					return
				}
				mu.Lock()
				pairs[incoming] = outgoing
				mu.Unlock()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(incoming, outgoing); done <- struct{}{} }()
				go func() { _, _ = io.Copy(outgoing, incoming); done <- struct{}{} }()
				<-done
				_ = incoming.Close()
				_ = outgoing.Close()
				<-done
				mu.Lock()
				delete(pairs, incoming)
				mu.Unlock()
			}()
		}
	}()
	drop := func() {
		mu.Lock()
		defer mu.Unlock()
		for a, b := range pairs {
			_ = a.Close()
			_ = b.Close()
		}
	}
	t.Cleanup(func() { _ = listener.Close(); drop(); workers.Wait() })
	return "https://" + listener.Addr().String(), drop
}

// After warmup, separately reset sender and receiver counters may differ in
// either direction. The receiver's actual rate must still be consistent.
func TestSpeedMeasurementAcceptsReceiverCountAndChecksSender(t *testing.T) {
	sample := SpeedSample{Bytes: 13221888, SentBytes: 13000000, Seconds: 8, Mbps: 13.221888}
	check := func(s SpeedSample) bool { return validSpeedMeasurement(&SpeedMeasurement{Upload: &s, Download: &s}) }
	if !check(sample) {
		t.Fatal("valid independently counted sender and receiver sample rejected")
	}
	if got := sampleFromProto(sampleProto(&sample)); !reflect.DeepEqual(got, &sample) {
		t.Fatal("sender and receiver counts lost over gRPC")
	}
	for _, change := range []func(*SpeedSample){
		func(s *SpeedSample) { s.SentBytes = 0 },
		func(s *SpeedSample) { s.Seconds = 41 },
		func(s *SpeedSample) { s.Seconds = 1 },
		func(s *SpeedSample) { s.Bytes = 0 },
		func(s *SpeedSample) { s.Mbps += 1 },
	} {
		bad := sample
		change(&bad)
		if check(bad) {
			t.Fatal("invalid sender or receiver sample accepted")
		}
	}
}

// A stale observation alone must not cancel an issued transfer, but a stale
// or revoked authorization must still prevent a retry.
func TestSpeedReissueRetainsPolicyGuards(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *Store)
	}{
		{"manual-suspension", func(t *testing.T, s *Store) {
			if err := s.SetAvailability("entry-example", "maintenance", time.Time{}, s.availability.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"account-expiry", func(_ *testing.T, s *Store) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.business.material.Plan.Accounts[0].Account.Plan.ExpiryTime = time.Now().Add(-time.Minute).UnixMilli()
		}},
		{"account-quota", func(_ *testing.T, s *Store) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.business.material.Plan.Accounts[0].Account.Plan.TotalBytes = 1
		}},
		{"credential-revoked", func(_ *testing.T, s *Store) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.business.material.Plan.Accounts[0].Credentials[0].Enabled = false
		}},
		{"business-unowned", func(_ *testing.T, s *Store) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.business.material.Ownership = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, original, entryCert, landingCert := subscriptionFixture(t, true)
			landingPlan := *s.nodes[landingCert].Desired.Landing
			transport := glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw==", PublicAddress: "11.177.0.2"}
			landingPlan.Transport = transport
			landingPlan.Sources[0].PublicAddress = "11.177.0.1"
			landing, err := NewDesired(landingPlan)
			if err != nil {
				t.Fatal(err)
			}
			entryPlan := *original.Entry
			entryPlan.Peers[0].Transport = transport
			entry, err := NewEntryDesired(entryPlan, *original.EntryNetwork)
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.nodes = map[string]Node{}
			s.mu.Unlock()
			if err = s.Put(Node{ID: "entry-example", CertificateID: entryCert, Desired: entry}); err != nil {
				t.Fatal(err)
			}
			if err = s.Put(Node{ID: "landing-example", CertificateID: landingCert, Desired: landing, RouteEntries: map[string]RouteEntry{"entry-example": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			entry = s.nodes[entryCert].Desired.clone()
			landing = s.nodes[landingCert].Desired.clone()
			s.mu.Unlock()
			reportRuntime(t, s, entryCert, entry)
			reportRuntime(t, s, landingCert, landing)
			s.mu.Lock()
			fresh := s.nodes[entryCert]
			fresh.ReportedAt = time.Now().Add(-2 * time.Minute)
			s.nodes[entryCert] = fresh
			_, _, _, staleErr := s.speedPairLocked("entry-example", "landing-example", true)
			_, _, _, retryErr := s.speedPairLocked("entry-example", "landing-example", false)
			s.mu.Unlock()
			if staleErr == nil || retryErr != nil {
				t.Fatalf("stale health behavior: %v / %v", staleErr, retryErr)
			}
			test.change(t, s)
			s.mu.Lock()
			_, _, _, err = s.speedPairLocked("entry-example", "landing-example", false)
			s.mu.Unlock()
			if err == nil {
				t.Fatal("issued task bypassed a policy change")
			}
		})
	}
}
