package control

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRouteChannelUsesVerifiedPeer(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	server, _, _ := identity(t, ca, key, true)
	entry, cert, _ := identity(t, ca, key, false)
	stranger, _, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s := store(t)
	d := artifact(1)
	if err := s.Put(Node{ID: "landing-a", CertificateID: strings.Repeat("a", 64), Desired: d}); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, strings.Repeat("a", 64), d)
	p := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	if err := s.AssignRouteCheck(CertificateID(cert), p); err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(Handler(s))
	var err error
	listener.TLS, err = ServerTLS(server, roots)
	if err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	defer listener.Close()
	client, err := NewClient(listener.URL, entry, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	other, err := NewClient(listener.URL, stranger, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	pending, err := client.RouteExchange(context.Background(), nil)
	if err != nil || len(pending) != 1 {
		t.Fatalf("assignment over TLS: %v %v", pending, err)
	}
	hidden, err := other.RouteExchange(context.Background(), nil)
	if err != nil || len(hidden) != 0 {
		t.Fatalf("foreign assignments disclosed: %v %v", hidden, err)
	}
	p = pending[0]
	r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now().UTC(), TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit, Passed: true}
	if _, err := other.RouteExchange(context.Background(), &r); err == nil {
		t.Fatal("other CA-signed peer submitted result")
	}
	pending, err = client.RouteExchange(context.Background(), &r)
	if err != nil || len(pending) != 0 {
		t.Fatalf("report over TLS: %v %v", pending, err)
	}
	if s.nodes[strings.Repeat("a", 64)].Checks[p.EntryID].Result == nil {
		t.Fatal("route result not persisted")
	}
}
