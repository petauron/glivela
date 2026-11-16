package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestStartupReconnectWakesWhenGRPCBecomesReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	conn, err := grpc.NewClient("passthrough:///"+address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: nodeControlBackoff(), MinConnectTimeout: time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &Client{grpc: conn, desiredWake: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ready := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { defer close(done); client.watchNodeConnectivity(ctx, ready) }()
	defer func() { cancel(); <-done }()
	conn.Connect()
	for state := conn.GetState(); state != connectivity.TransientFailure; state = conn.GetState() {
		if !conn.WaitForStateChange(ctx, state) {
			t.Fatal("did not observe an unavailable control channel")
		}
	}
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	go server.Serve(listener)
	defer server.Stop()
	select {
	case <-client.desiredWake:
	case <-ctx.Done():
		t.Fatal("startup recovery was not woken when the control channel became ready")
	}
	if conn.GetState() != connectivity.Ready {
		t.Fatal("received a wake without a ready control connection")
	}
}

func TestStartupRecoveryAfterControlNetworkReturns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, worker := nativeFixture(t)
	desired := routedEntryArtifact(t)
	driver := &startupIdentityFixture{driverFixture: worker, identity: *desired.EntryNetwork.Source, ready: true}
	r.Driver = driver
	if err := r.Apply(ctx, desired); err != nil {
		t.Fatal(err)
	}
	worker.running = false
	driver.acceptErr = errors.New("network is not ready")
	restarted := &NativeRuntime{Directory: r.Directory, Driver: driver}
	if err := restarted.Recover(ctx); !errors.Is(err, ErrStartupAcceptance) {
		t.Fatal(err)
	}
	driver.acceptErr = nil
	restarted.startupRetryAt = time.Now().Add(-time.Second)
	_, ca, key := identity(t, nil, nil, false)
	serverCert, _, _ := identity(t, ca, key, true)
	nodeCert, leaf, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	store := store(t)
	if err := store.Put(Node{ID: "entry-example", CertificateID: CertificateID(leaf), Desired: desired}); err != nil {
		t.Fatal(err)
	}
	app, err := NewServer("127.0.0.1:0", store, serverCert, roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	client, err := NewClient("https://"+address, nodeCert, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); client.RunNodeUpdates(ctx) }()
	result := make(chan bool, 1)
	nodeDone := make(chan struct{})
	node := NodeRunner{Client: client, Runtime: restarted}
	go func() {
		defer close(nodeDone)
		_ = node.Run(ctx, time.Second, func(err error) {
			if err == nil {
				select {
				case result <- worker.running && worker.starts == 3:
				default:
				}
			}
		})
	}()
	defer func() { cancel(); <-nodeDone; <-watchDone }()
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-result:
		t.Fatal("offline controller started the worker")
	default:
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: app.Handler, TLSConfig: app.TLSConfig.Clone(), HTTP2: app.HTTP2}
	go server.Serve(tls.NewListener(listener, server.TLSConfig))
	defer server.Close()
	select {
	case recovered := <-result:
		if !recovered {
			t.Fatal("authenticated startup recovery did not start the owned worker")
		}
	case <-ctx.Done():
		t.Fatal("startup did not recover when the mTLS controller became reachable")
	}
}
