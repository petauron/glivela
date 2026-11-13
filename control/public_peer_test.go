package control

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func publicPeerFixture(t *testing.T) (*Store, string, string, landingAcceptanceRequest) {
	t.Helper()
	s, _, entryCert, landingCert := subscriptionFixture(t, true)
	transport := glivela.PrivateTransport{Protocol: "ss2022", PublicAddress: "9.9.9.9", Port: 24000, Key: "MDEyMzQ1Njc4OWFiY2RlZg=="}
	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	plan.Peers[0].Transport, plan.Peers[0].Port = transport, 24000
	plan.Revision++
	var err error
	entry.Desired, err = NewEntryDesired(plan, *entry.Desired.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(entry); err != nil {
		t.Fatal(err)
	}
	target := s.nodes[landingCert]
	landingPlan := *target.Desired.Landing
	landingPlan.Revision++
	landingPlan.Transport = transport
	landingPlan.Sources[0].TCPOnly = true
	landingPlan.Sources[0].PublicAddress = "8.8.4.4"
	target.Desired, err = NewDesired(landingPlan)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(target); err != nil {
		t.Fatal(err)
	}
	target = s.nodes[landingCert]
	identity := entry.Desired.EntryNetwork.Peers[0].Identity
	_, err = s.Exchange(context.Background(), landingCert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity})
	if err != nil {
		t.Fatal(err)
	}
	entry = s.nodes[entryCert]
	return s, entryCert, landingCert, landingAcceptanceRequest{SnapshotID: entry.ID, PeerID: target.ID, Revision: entry.Desired.Revision, ConfigSHA256: entry.Desired.ConfigSHA256}
}

func TestPublicPeerAcceptanceRequiresFreshExactMutualEnrollment(t *testing.T) {
	for _, fault := range []string{"none", "missing-report", "stale", "wrong-identity", "wrong-source-certificate", "wrong-source-address", "wrong-public-source", "wrong-target", "wrong-entry-revision", "unassigned-peer", "foreign-entry"} {
		t.Run(fault, func(t *testing.T) {
			s, entryCert, landingCert, request := publicPeerFixture(t)
			node := s.nodes[landingCert]
			switch fault {
			case "missing-report":
				node.Receipt.ManagementIdentity = nil
			case "stale":
				node.ReportedAt = time.Now().Add(-24 * time.Hour)
			case "wrong-identity":
				identity := *node.Receipt.ManagementIdentity
				identity.PublicKey = "nodekey:replacement"
				node.Receipt.ManagementIdentity = &identity
			case "wrong-source-certificate":
				r := node.RouteEntries[request.SnapshotID]
				r.CertificateID = landingCert
				node.RouteEntries[request.SnapshotID] = r
			case "wrong-source-address":
				r := node.RouteEntries[request.SnapshotID]
				r.Address = "100.64.0.99"
				node.RouteEntries[request.SnapshotID] = r
			case "wrong-public-source":
				node.Desired.Landing.Sources[0].PublicAddress = ""
			case "wrong-target":
				node.Desired.Landing.Transport.PublicAddress = "1.1.1.1"
			case "wrong-entry-revision":
				request.Revision++
			case "unassigned-peer":
				request.PeerID = "other-landing"
			case "foreign-entry":
				entryCert = landingCert
			}
			s.nodes[landingCert] = node
			before := s.nodes[landingCert].Desired.clone()
			result, err := s.publicPeerAcceptance(entryCert, request)
			if (err == nil) != (fault == "none") {
				t.Fatal("identity acceptance differs", fault, err)
			}
			if err == nil && (result.Identity != *node.Receipt.ManagementIdentity || result.EntryID != request.SnapshotID || result.LandingID != request.PeerID || result.CheckedAt.IsZero()) {
				t.Fatal("proof not bound to exact enrollment")
			}
			if !reflect.DeepEqual(before, s.nodes[landingCert].Desired) {
				t.Fatal("read-only identity check changed policy")
			}
		})
	}
}

func TestPublicPeerAcceptanceOverMutualTLS(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	serverIdentity, _, _ := identity(t, ca, key, true)
	entryIdentity, entryCert, _ := identity(t, ca, key, false)
	landingIdentity, landingCert, _ := identity(t, ca, key, false)
	s, oldEntry, oldLanding, _ := publicPeerFixture(t)
	entry, target := s.nodes[oldEntry], s.nodes[oldLanding]
	delete(s.nodes, oldEntry)
	delete(s.nodes, oldLanding)
	entry.CertificateID, target.CertificateID = CertificateID(entryCert), CertificateID(landingCert)
	route := target.RouteEntries[entry.ID]
	route.CertificateID = entry.CertificateID
	target.RouteEntries[entry.ID] = route
	s.nodes[entry.CertificateID], s.nodes[target.CertificateID] = entry, target
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server, err := NewServer("127.0.0.1:0", s, serverIdentity, roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var stallNext atomic.Bool
	handler := server.Handler
	listener := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/LandingAcceptance") {
			calls.Add(1)
			if stallNext.Swap(false) {
				<-r.Context().Done()
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	listener.EnableHTTP2 = true
	listener.TLS = server.TLSConfig.Clone()
	listener.Config.HTTP2 = server.HTTP2
	listener.StartTLS()
	defer listener.Close()
	client, err := NewClient(listener.URL, entryIdentity, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer := entry.Desired.EntryNetwork.Peers[0]
	if proof := client.VerifyPublicPeer(context.Background(), entry.Desired, peer); proof.State != "authenticated" {
		t.Fatal("mTLS public identity refused", proof)
	}
	stallNext.Store(true)
	beforeRetry := calls.Load()
	if proof := client.VerifyPublicPeer(context.Background(), entry.Desired, peer); proof.State != "authenticated" || calls.Load()-beforeRetry != 2 || proof.CheckedAt.Sub(proof.StartedAt) > 3*time.Second {
		t.Fatal("one transient RPC timeout did not obtain a fresh bounded proof", proof, calls.Load()-beforeRetry)
	}
	foreign, err := NewClient(listener.URL, landingIdentity, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	beforeRefusal := calls.Load()
	if proof := foreign.VerifyPublicPeer(context.Background(), entry.Desired, peer); proof.State == "authenticated" || calls.Load()-beforeRefusal != 1 {
		t.Fatal("other enrolled role obtained entry-scoped proof")
	}
	s.mu.Lock()
	target.Receipt.ManagementIdentity = nil
	s.nodes[target.CertificateID] = target
	s.mu.Unlock()
	if proof := client.VerifyPublicPeer(context.Background(), entry.Desired, peer); proof.State == "authenticated" {
		t.Fatal("missing landing identity silently accepted")
	}
}
