package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestManagementRouteVerificationOverMutualTLS(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	serverIdentity, _, _ := identity(t, ca, key, true)
	adminIdentity, adminCert, _ := identity(t, ca, key, false)
	entryIdentity, entryCert, _ := identity(t, ca, key, false)
	landingIdentity, landingCert, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s := store(t)
	d := artifact(1)
	landingCertificate := CertificateID(landingCert)
	server, err := NewServer("127.0.0.1:0", s, serverIdentity, roots, []string{CertificateID(adminCert)})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server.Handler)
	listener.TLS = server.TLSConfig
	listener.StartTLS()
	defer listener.Close()
	client := func(cert tls.Certificate) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	admin, entryHTTP := client(adminIdentity), client(entryIdentity)
	post := func(c *http.Client, path string, body any, want int) *http.Response {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response, err := c.Post(listener.URL+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		if response.StatusCode != want {
			t.Fatalf("%s: status %d, want %d", path, response.StatusCode, want)
		}
		return response
	}
	enrollment := map[string]any{"id": "landing-a", "certificateId": landingCertificate, "plan": d.Landing, "routeEntries": map[string]RouteEntry{"entry-a": {CertificateID: CertificateID(entryCert), Address: "100.64.0.3"}}}
	post(entryHTTP, "/v1/admin/landings", enrollment, http.StatusForbidden)
	response := post(admin, "/v1/admin/landings", enrollment, http.StatusAccepted)
	var revision struct {
		Revision     uint64
		ConfigSHA256 string
	}
	if json.NewDecoder(response.Body).Decode(&revision) != nil || revision.Revision != d.Revision || revision.ConfigSHA256 != d.ConfigSHA256 {
		t.Fatal("management response did not bind generated configuration", revision)
	}
	response.Body.Close()
	landingClient, err := NewClient(listener.URL, landingIdentity, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer landingClient.Close()
	if got, err := landingClient.Exchange(context.Background(), nil); err != nil || got.ConfigSHA256 != d.ConfigSHA256 || got.Validate() != nil {
		t.Fatal("generated policy not delivered to enrolled landing", err)
	}
	p := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	inventory := map[string]any{"checks": []RouteCheck{{CertificateID: CertificateID(entryCert), Request: p}}}
	post(entryHTTP, "/v1/admin/route-checks", inventory, http.StatusForbidden)
	post(admin, "/v1/exchange", map[string]any{}, http.StatusForbidden)
	post(admin, "/v1/admin/route-checks", inventory, http.StatusConflict)
	if _, err := landingClient.Exchange(context.Background(), &glivela.AppliedReceipt{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, RuntimeReady: true}); err != nil {
		t.Fatal(err)
	}
	post(admin, "/v1/admin/route-checks", inventory, http.StatusAccepted)
	acceptance := map[string]any{"landingId": p.LandingID, "snapshotId": p.SnapshotID, "revision": p.Revision, "configSha256": p.ConfigSHA256}
	read := func(want bool) {
		t.Helper()
		response := post(admin, "/v1/admin/route-acceptance", acceptance, http.StatusOK)
		var status RouteAcceptance
		if json.NewDecoder(response.Body).Decode(&status) != nil || !status.RuntimeReady || status.RoutesPassed != want {
			t.Fatalf("incorrect business acceptance: %+v", status)
		}
		response.Body.Close()
	}
	read(false)
	entry, err := NewClient(listener.URL, entryIdentity, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	pending, err := entry.RouteExchange(context.Background(), nil)
	if err != nil || len(pending) != 1 {
		t.Fatal("managed assignment not delivered", err)
	}
	p = pending[0]
	result := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit, Passed: true}
	if _, err := entry.RouteExchange(context.Background(), &result); err != nil {
		t.Fatal(err)
	}
	read(true)
	post(admin, "/v1/admin/route-checks", map[string]any{"checks": []RouteCheck{{CertificateID: CertificateID(adminCert), Request: p}}}, http.StatusBadRequest)
	post(admin, "/v1/admin/route-acceptance", map[string]any{"unknown": true}, http.StatusBadRequest)
	post(entryHTTP, "/v1/admin/route-acceptance", acceptance, http.StatusForbidden)
	post(admin, "/v1/admin/landings", map[string]any{"id": "landing-a", "certificateId": CertificateID(adminCert), "plan": d.Landing}, http.StatusBadRequest)
	post(admin, "/v1/admin/landings", map[string]any{"id": "landing-a", "certificateId": landingCertificate, "plan": d.Landing, "config": "arbitrary core configuration"}, http.StatusBadRequest)
	next := artifact(2)
	post(admin, "/v1/admin/landings", map[string]any{"id": "landing-a", "certificateId": landingCertificate, "plan": next.Landing}, http.StatusAccepted)
	if got, err := landingClient.Exchange(context.Background(), &glivela.AppliedReceipt{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, RuntimeReady: true}); err != nil || got.Revision != 2 {
		t.Fatal("stale receipt prevented delivery of updated policy", err)
	}
	post(admin, "/v1/admin/landings", enrollment, http.StatusConflict)
	if s.nodes[landingCertificate].Receipt != nil || len(s.nodes[landingCertificate].Checks) != 0 {
		t.Fatal("updated policy retained old success")
	}
	reloaded, err := OpenStore(s.path)
	if err != nil || reloaded.nodes[landingCertificate].ID != "landing-a" || reloaded.nodes[landingCertificate].Desired.Revision != 2 {
		t.Fatal("managed update lost identity or revision on reload", err)
	}
}

func TestManagementCertificateInventoryFailsClosed(t *testing.T) {
	s := store(t)
	certificate := strings.Repeat("a", 64)
	for _, admins := range [][]string{{"not-a-fingerprint"}, {certificate, certificate}} {
		if _, err := controllerHandler(s, admins); err == nil {
			t.Fatal("invalid administrative inventory accepted")
		}
	}
	if err := s.Put(Node{ID: "landing-a", CertificateID: certificate, Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := controllerHandler(s, []string{certificate}); err == nil {
		t.Fatal("node credential granted management authority")
	}
}
