package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/petauron/glivela/landing"
)

type startupStatusTransport func(*http.Request) (*http.Response, error)

func (f startupStatusTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestStartupSelfIdentityRequiresRunningExactLocalIdentity(t *testing.T) {
	expected := landing.PeerIdentity{ID: "entry-mesh", PublicKey: "nodekey:entry", Address: "100.64.0.3"}
	for _, item := range []struct {
		name, state, id, key, address string
		valid                         bool
	}{
		{"ready", "Running", expected.ID, expected.PublicKey, expected.Address, true},
		{"not-ready", "Starting", expected.ID, expected.PublicKey, expected.Address, false},
		{"changed-id", "Running", "other-node", expected.PublicKey, expected.Address, false},
		{"changed-key", "Running", expected.ID, "nodekey:other", expected.Address, false},
		{"changed-address", "Running", expected.ID, expected.PublicKey, "100.64.0.9", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"BackendState": item.state,
				"Self":         map[string]any{"ID": item.id, "PublicKey": item.key, "TailscaleIPs": []string{item.address}},
			})
			if err != nil {
				t.Fatal(err)
			}
			checker := &landing.LinkChecker{HTTPClient: &http.Client{Transport: startupStatusTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			defer checker.Close()
			if err := verifyStartupSelfIdentity(context.Background(), expected, checker); (err == nil) != item.valid {
				t.Fatalf("local identity acceptance differs: %v", err)
			}
		})
	}
}

type startupIdentityFixture struct {
	*driverFixture
	identity  landing.PeerIdentity
	ready     bool
	stopErr   error
	acceptErr error
}

func (f *startupIdentityFixture) verifyStartupIdentity(_ context.Context, desired Desired) error {
	if !f.ready || desired.EntryNetwork == nil || desired.EntryNetwork.Source == nil || f.identity != *desired.EntryNetwork.Source {
		return errors.New("private identity unavailable or changed")
	}
	return nil
}

func (f *startupIdentityFixture) Stop(ctx context.Context, desired Desired) error {
	if f.stopErr != nil {
		return f.stopErr
	}
	return f.driverFixture.Stop(ctx, desired)
}

func (f *startupIdentityFixture) Activate(ctx context.Context, desired Desired, previous *Desired) error {
	if err := f.driverFixture.Activate(ctx, desired, previous); err != nil {
		return err
	}
	return f.acceptErr
}

func TestStartupRetryAfterAcceptanceFailure(t *testing.T) {
	ctx := context.Background()
	r, worker := nativeFixture(t)
	desired := routedEntryArtifact(t)
	driver := &startupIdentityFixture{driverFixture: worker, identity: *desired.EntryNetwork.Source, ready: true}
	r.Driver = driver
	if err := r.Apply(ctx, desired); err != nil {
		t.Fatal(err)
	}
	worker.running = false
	driver.acceptErr = errors.New("startup route or identity probe failed")
	restarted := &NativeRuntime{Directory: r.Directory, Driver: driver}
	if err := restarted.Recover(ctx); !errors.Is(err, ErrStartupAcceptance) || worker.running || worker.starts != 2 {
		t.Fatal("failed startup acceptance did not stop the worker", err)
	}
	driver.acceptErr = nil
	restarted.startupRetryAt = time.Now().Add(-time.Second)
	client := &fakeClient{desired: desired}
	node := NodeRunner{Client: client, Runtime: restarted}
	if err := node.Step(ctx); err != nil || !worker.running || worker.starts != 3 || client.reports != 2 {
		t.Fatal("startup acceptance did not recover without a new revision", err)
	}
}

func TestStartupRetryRequiresEnrolledMutualTLS(t *testing.T) {
	ctx := context.Background()
	r, worker := nativeFixture(t)
	desired := routedEntryArtifact(t)
	driver := &startupIdentityFixture{driverFixture: worker, identity: *desired.EntryNetwork.Source, ready: true}
	r.Driver = driver
	if err := r.Apply(ctx, desired); err != nil {
		t.Fatal(err)
	}
	worker.running = false
	worker.activationError = func(Desired) error { return errors.New("startup temporarily unavailable") }
	restarted := &NativeRuntime{Directory: r.Directory, Driver: driver}
	if err := restarted.Recover(ctx); !errors.Is(err, ErrStartupAcceptance) {
		t.Fatal(err)
	}
	worker.activationError = nil
	restarted.startupRetryAt = time.Now().Add(-time.Second)

	_, ca, key := identity(t, nil, nil, false)
	server, _, _ := identity(t, ca, key, true)
	allowed, certificate, _ := identity(t, ca, key, false)
	unknown, _, _ := identity(t, ca, key, false)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s := store(t)
	if err := s.Put(Node{ID: "entry-example", CertificateID: CertificateID(certificate), Desired: desired}); err != nil {
		t.Fatal(err)
	}
	app, err := NewServer("127.0.0.1:0", s, server, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(app.Handler)
	listener.EnableHTTP2 = true
	listener.TLS = app.TLSConfig.Clone()
	listener.Config.HTTP2 = app.HTTP2
	listener.StartTLS()
	defer listener.Close()
	denied, err := NewClient(listener.URL, unknown, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	if err := (NodeRunner{Client: denied, Runtime: restarted}).Step(ctx); err == nil || worker.running || worker.starts != 1 {
		t.Fatal("unenrolled identity started the worker", err)
	}
	client, err := NewClient(listener.URL, allowed, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := (NodeRunner{Client: client, Runtime: restarted}).Step(ctx); err != nil || !worker.running || worker.starts != 2 {
		t.Fatal("enrolled controller did not recover the worker", err)
	}
	if s.nodes[CertificateID(certificate)].Receipt == nil {
		t.Fatal("recovered worker was not reported to the controller")
	}
}

func TestStartupRetryRequiresIdentityAndAuthenticatedAssignment(t *testing.T) {
	ctx := context.Background()
	r, worker := nativeFixture(t)
	desired := routedEntryArtifact(t)
	driver := &startupIdentityFixture{driverFixture: worker, identity: *desired.EntryNetwork.Source}
	r.Driver = driver
	if err := r.Apply(ctx, desired); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(r.Directory, "runtime.json")
	configPath := filepath.Join(r.Directory, "config.json")
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	worker.running = false
	restarted := &NativeRuntime{Directory: r.Directory, Driver: driver}
	if err := restarted.Recover(ctx); !errors.Is(err, ErrStartupAcceptance) || worker.running || worker.starts != 1 {
		t.Fatal("unready private network did not leave worker stopped", err)
	}
	client := &fakeClient{desired: desired}
	node := NodeRunner{Client: client, Runtime: restarted}
	if node.StepTimeout() != 90*time.Second || node.Step(ctx) != nil || worker.starts != 1 {
		t.Fatal("startup backoff did not prevent an early attempt")
	}
	forceRetry := func() { restarted.startupRetryAt = time.Now().Add(-time.Second) }
	forceRetry()
	client.err = errors.New("controller offline")
	if node.Step(ctx) == nil || worker.starts != 1 {
		t.Fatal("startup retry ran without an authenticated controller")
	}
	client.err = nil
	driver.ready = true
	driver.identity.PublicKey = "nodekey:changed"
	forceRetry()
	if node.Step(ctx) == nil || worker.running || worker.starts != 1 {
		t.Fatal("changed local private identity started the worker")
	}
	driver.identity = *desired.EntryNetwork.Source
	changed := desired.clone()
	changed.EntryNetwork.Source.PublicKey = "nodekey:other"
	if changed.Validate() != nil || changed.ConfigSHA256 != desired.ConfigSHA256 {
		t.Fatal("fixture must alter only the assigned private identity")
	}
	client.desired = changed
	forceRetry()
	if node.Step(ctx) == nil || worker.running || worker.starts != 1 {
		t.Fatal("same revision with changed identity was accepted")
	}
	client.desired = desired
	prepared := filepath.Join(r.Directory, "transport-prepared.json")
	if err := os.WriteFile(prepared, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	forceRetry()
	if node.Step(ctx) == nil || worker.running || worker.starts != 1 {
		t.Fatal("startup retry bypassed transport maintenance")
	}
	if err := os.Remove(prepared); err != nil {
		t.Fatal(err)
	}
	worker.validErr = errors.New("temporary validation failure")
	forceRetry()
	if node.Step(ctx) == nil || worker.running || worker.starts != 1 {
		t.Fatal("failed validation started the worker")
	}
	worker.validErr = nil
	forceRetry()
	reports := client.reports
	if err := node.Step(ctx); err != nil || !worker.running || worker.starts != 2 || client.reports != reports+2 {
		t.Fatal("matching authenticated startup did not recover and report", err)
	}
	if node.StepTimeout() != 30*time.Second {
		t.Fatal("startup retry remained armed after recovery")
	}
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(journalBefore, journalAfter) {
		t.Fatal("startup recovery changed the committed journal", err)
	}
	configAfter, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(configBefore, configAfter) {
		t.Fatal("startup recovery changed the committed configuration", err)
	}
	worker.running = false
	if node.Step(ctx) == nil || worker.starts != 2 {
		t.Fatal("ordinary later health loss triggered startup recovery")
	}
}

func TestStartupRetryRefusesUnconfirmedStopAndTampering(t *testing.T) {
	ctx := context.Background()
	for _, stopFails := range []bool{false, true} {
		r, worker := nativeFixture(t)
		desired := routedEntryArtifact(t)
		driver := &startupIdentityFixture{driverFixture: worker, identity: *desired.EntryNetwork.Source}
		r.Driver = driver
		if err := r.Apply(ctx, desired); err != nil {
			t.Fatal(err)
		}
		worker.running = false
		if stopFails {
			driver.stopErr = errors.New("stop could not be confirmed")
		}
		restarted := &NativeRuntime{Directory: r.Directory, Driver: driver}
		err := restarted.Recover(ctx)
		if stopFails {
			if err == nil || errors.Is(err, ErrStartupAcceptance) || restarted.startupRecoveryPending() {
				t.Fatal("unconfirmed stop armed automatic recovery", err)
			}
			continue
		}
		if !errors.Is(err, ErrStartupAcceptance) {
			t.Fatal(err)
		}
		driver.ready = true
		restarted.startupRetryAt = time.Now().Add(-time.Second)
		if err := os.WriteFile(filepath.Join(r.Directory, "config.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		node := NodeRunner{Client: &fakeClient{desired: desired}, Runtime: restarted}
		if node.Step(ctx) == nil || worker.running || worker.starts != 1 {
			t.Fatal("tampered committed config was restarted")
		}
	}
}
