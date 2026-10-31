package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

// The channel and persistence are real. Worker execution uses the existing
// journal fixture, not Docker; this does NOT prove entry container adoption.
func TestEntryDesiredDeliveryAndUpdatesOverMutualTLS(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	serverIdentity, _, _ := identity(t, ca, key, true)
	adminIdentity, adminCert, _ := identity(t, ca, key, false)
	entryA, certA, _ := identity(t, ca, key, false)
	entryB, certB, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s := store(t)
	server, err := NewServer("127.0.0.1:0", s, serverIdentity, roots, []string{CertificateID(adminCert)})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server.Handler)
	listener.TLS = server.TLSConfig
	listener.StartTLS()
	defer listener.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{adminIdentity}, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	admin := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	post := func(id, certificate string, desired Desired, want int) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"id": id, "certificateId": certificate, "plan": desired.Entry, "network": desired.EntryNetwork})
		if err != nil {
			t.Fatal(err)
		}
		response, err := admin.Post(listener.URL+"/v1/admin/entries", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("entry enrollment status %d, want %d", response.StatusCode, want)
		}
	}
	a, b := entryArtifact(t, "entry-a", 1), entryArtifact(t, "entry-b", 1)
	post("entry-a", CertificateID(certA), a, http.StatusAccepted)
	post("entry-b", CertificateID(certB), b, http.StatusAccepted)
	post("entry-b", CertificateID(adminCert), b, http.StatusBadRequest)
	post("wrong-entry", CertificateID(certA), a, http.StatusConflict)
	for _, includeNull := range []bool{false, true} {
		request := map[string]any{"id": "entry-a", "certificateId": CertificateID(certA), "plan": a.Entry}
		if includeNull {
			request["network"] = nil
		}
		raw, _ := json.Marshal(request)
		response, err := admin.Post(listener.URL+"/v1/admin/entries", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatal("missing/null entry network policy accepted")
		}
	}
	clientA, err := NewClient(listener.URL, entryA, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	response, err := clientA.http.Post(listener.URL+"/v1/admin/entries", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("entry certificate acquired administration access")
	}
	clientB, err := NewClient(listener.URL, entryB, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()
	ctx := context.Background()
	gotA, err := clientA.Exchange(ctx, nil)
	if err != nil || gotA.Entry == nil || gotA.Landing != nil || gotA.Entry.RealityEndpoints[0].EntryID != "entry-a" || gotA.ConfigSHA256 != a.ConfigSHA256 || bytes.Contains(gotA.Config, []byte(b.Entry.Credentials[0].ProtocolID)) {
		t.Fatal("entry received another identity or changed configuration", err)
	}
	gotB, err := clientB.Exchange(ctx, nil)
	if err != nil || gotB.ConfigSHA256 != b.ConfigSHA256 {
		t.Fatal("second entry lost its configuration", err)
	}
	_, err = clientA.Exchange(ctx, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: 1, ConfigSHA256: b.ConfigSHA256, RuntimeReady: true}})
	if err != nil || s.nodes[CertificateID(certA)].Receipt != nil || s.nodes[CertificateID(certB)].Receipt != nil {
		t.Fatal("one entry submitted another entry's readiness", err)
	}
	runtime, worker := nativeFixture(t)
	runner := NodeRunner{Client: clientA, Runtime: runtime}
	if err := runner.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if worker.starts != 1 || s.nodes[CertificateID(certA)].Receipt == nil {
		t.Fatal("entry report was not revision-bound")
	}
	if err := runner.Step(ctx); err != nil || worker.starts != 1 {
		t.Fatal("unchanged desired restarted the worker", err)
	}
	nextPlan := a.clone().Entry
	nextPlan.Revision = 2
	nextPlan.Credentials[0].Credential.User = "entry-a-updated-user"
	next, err := NewEntryDesired(*nextPlan, *a.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	post("entry-a", CertificateID(certA), next, http.StatusAccepted)
	if err := runner.Step(ctx); err != nil || worker.starts != 2 {
		t.Fatal("entry update was not reconciled", err)
	}
	post("entry-a", CertificateID(certA), a, http.StatusConflict)
	loaded, err := OpenStore(s.path)
	if err != nil || loaded.nodes[CertificateID(certA)].Desired.Revision != 2 || loaded.nodes[CertificateID(certA)].Desired.Entry.Credentials[0].ProtocolID != a.Entry.Credentials[0].ProtocolID {
		t.Fatal("restart/update regenerated entry credential identity", err)
	}
	// The TLS channel and runtime journal are real; activation is a test
	// worker. This proves policy-only revisions are delivered/applied rather
	// than skipped by config-hash deduplication, not actual firewall acceptance.
	routed := withRoutedEntry(t, next)
	routed.Entry.Revision = 3
	routed, err = NewEntryDesired(*routed.Entry, *routed.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	post("entry-a", CertificateID(certA), routed, http.StatusAccepted)
	if err := runner.Step(ctx); err != nil || worker.starts != 3 {
		t.Fatal("routed entry not applied", err)
	}
	changed := routed.clone()
	changed.EntryNetwork.Peers[0].ExpectedExit = "1.1.1.1"
	post("entry-a", CertificateID(certA), changed, http.StatusConflict)
	changed.Entry.Revision = 4
	changed, err = NewEntryDesired(*changed.Entry, *changed.EntryNetwork)
	if err != nil || changed.ConfigSHA256 != routed.ConfigSHA256 {
		t.Fatal("network-only fixture changed core configuration", err)
	}
	post("entry-a", CertificateID(certA), changed, http.StatusAccepted)
	if s.nodes[CertificateID(certA)].Receipt != nil {
		t.Fatal("network change retained previous ready receipt")
	}
	if err := runner.Step(ctx); err != nil || worker.starts != 4 || worker.active.EntryNetwork.Peers[0].ExpectedExit != "1.1.1.1" {
		t.Fatal("policy-only revision skipped activation", err)
	}
	if err := runner.Step(ctx); err != nil || worker.starts != 4 {
		t.Fatal("unchanged policy repeated activation", err)
	}
	restarted := &NativeRuntime{Directory: runtime.Directory, Driver: worker}
	journal, err := restarted.journal()
	if err != nil || journal.Current == nil || journal.Current.EntryNetwork.Peers[0].ExpectedExit != "1.1.1.1" {
		t.Fatal("runtime journal lost new transport policy", err)
	}
}
