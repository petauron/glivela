package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func unusedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestControllerAndSubscriptionListenersStopTogether(t *testing.T) {
	// A disposable trusted TLS identity; no disabled certificate verification.
	template := httptest.NewTLSServer(http.NotFoundHandler())
	configuration := template.TLS.Clone()
	leaf := template.Certificate()
	template.Close()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	controlAddress, subscriptionAddress := unusedLoopbackAddress(t), unusedLoopbackAddress(t)
	for attempt := 0; controlAddress == subscriptionAddress; attempt++ {
		if attempt == 10 {
			t.Fatal("could not allocate distinct fixture ports")
		}
		subscriptionAddress = unusedLoopbackAddress(t)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	control := &http.Server{Addr: controlAddress, Handler: handler, TLSConfig: configuration, ReadHeaderTimeout: time.Second}
	subscription := &http.Server{Addr: subscriptionAddress, Handler: handler, ReadHeaderTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveController(ctx, control, subscription) }()
	t.Cleanup(func() { cancel(); _ = control.Close(); _ = subscription.Close() })
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, url := range []string{"https://" + controlAddress, "http://" + subscriptionAddress} {
		deadline := time.Now().Add(3 * time.Second)
		for {
			response, err := client.Get(url)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != 204 {
					t.Fatal("unexpected fixture status")
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("listeners did not start", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// A failed origin cannot leave a half-running controller claiming a
	// successful complete start. The other listener is closed as well.
	if err := subscription.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("listener failure not returned", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sibling listener was left running")
	}
	if response, err := client.Get("https://" + controlAddress); err == nil {
		response.Body.Close()
		t.Fatal("control survived subscription listener failure")
	}
}

func TestControllerListenerCancellationDoesNotStartOrLeakOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	control := &http.Server{Addr: "127.0.0.1:0", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	origin := &http.Server{Addr: "127.0.0.1:0"}
	if err := serveController(ctx, control, origin); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
