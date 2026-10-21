package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func TestStoredLegacyHealthLoadsWithoutBecomingCurrentProof(t *testing.T) {
	s := store(t)
	d := twoPeerEntry(t)
	observation := healthyEntryObservation(d, time.Now())
	for id, peer := range observation.EntryHealth.Peers {
		peer.Status.SecurityCheckedAt = time.Time{}
		observation.EntryHealth.Peers[id] = peer
	}
	cert := strings.Repeat("a", 64)
	node := Node{ID: "entry-a", CertificateID: cert, Desired: d, Receipt: &observation}
	raw, err := json.Marshal([]Node{node})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	retained := loaded.nodes[cert]
	if retained.Desired.ConfigSHA256 != d.ConfigSHA256 || retained.CertificateID != cert || retained.Receipt == nil {
		t.Fatal("retained identity/configuration/receipt changed")
	}
	if validateEntryHealth(d, retained.Receipt.EntryHealth) == nil {
		t.Fatal("historical proof was accepted as current health")
	}
	after, err := os.ReadFile(s.path)
	if err != nil || string(after) != string(raw) {
		t.Fatal("load rewrote historical data", err)
	}
	for id, peer := range observation.EntryHealth.Peers {
		peer.Status.ExitIP = "192.0.2.254"
		observation.EntryHealth.Peers[id] = peer
		break
	}
	if validateStoredEntryHealth(d, observation.EntryHealth) == nil {
		t.Fatal("invalid historical identity accepted")
	}
}

// Synthetic producer evidence for controller contract tests only. Actual
// Docker/process/gate acceptance is not represented by these fixture values.
func healthyEntryObservation(desired Desired, now time.Time) Observation {
	health := &EntryHealthReport{SampledAt: now, Peers: map[string]EntryPeerObservation{}}
	if desired.EntryNetwork.Source != nil {
		source := *desired.EntryNetwork.Source
		health.Source = &source
	}
	for _, peer := range desired.EntryNetwork.Peers {
		health.Peers[peer.EgressID] = EntryPeerObservation{Identity: peer.Identity, Status: landing.MonitorStatus{Revision: desired.Revision, State: "healthy", LinkState: "direct", Stage: "complete", Reason: "direct_and_business_ready", TCP: true, ExitIP: peer.ExpectedExit, StartedAt: now.Add(-time.Second), SecurityCheckedAt: now.Add(-500 * time.Millisecond), CheckedAt: now.Add(-100 * time.Millisecond), LastHealthyAt: now.Add(-100 * time.Millisecond), AllowedUntil: now.Add(8 * time.Second), DurationMS: 900}}
	}
	return Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: desired.Revision, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}, EntryHealth: health}
}

func twoPeerEntry(t *testing.T) Desired {
	t.Helper()
	d := withRoutedEntry(t, entryArtifact(t, "entry-a", 1))
	plan := *d.Entry
	protocolID := uuid.NewString()
	credential := glivela.Credential{ID: "second-route", AccountID: plan.Credentials[0].Credential.AccountID, Kind: glivela.RouteCredential, User: "second-route-user", Identity: glivela.Identity(protocolID), EntryID: "entry-a", EgressID: "landing-other", Enabled: true}
	plan.Credentials = append(plan.Credentials, glivela.CredentialMaterial{Credential: credential, ProtocolID: protocolID})
	plan.Grants = append(plan.Grants, glivela.RouteGrant{ID: "second-grant", AccountID: credential.AccountID, EntryID: credential.EntryID, EgressID: credential.EgressID, InboundTag: plan.RealityEndpoints[0].InboundTag, Base: plan.Credentials[0].Credential, Route: credential, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1})
	plan.Peers = append(plan.Peers, glivela.RoutePeer{EgressID: "landing-other", Address: "100.64.0.9", Port: 1080, ExitFamily: glivela.EgressIPv4Only})
	network := d.EntryNetwork.clone()
	network.Peers = append(network.Peers, EntryPeer{EgressID: "landing-other", Identity: landing.PeerIdentity{ID: "other-mesh", PublicKey: "nodekey:other", Address: "100.64.0.9"}, Target: "https://probe.example.test/exit", ExpectedExit: "1.1.1.1"})
	var err error
	d, err = NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func passLandingCheck(t *testing.T, s *Store, targetCertificate, entryCertificate string, entry Desired) {
	t.Helper()
	target := s.nodes[targetCertificate]
	var peer EntryPeer
	for _, candidate := range entry.EntryNetwork.Peers {
		if candidate.EgressID == target.ID {
			peer = candidate
		}
	}
	request := RouteProbe{SnapshotID: "snapshot-" + target.ID, EntryID: "entry-a", LandingID: target.ID, Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256, SOCKSAddress: net.JoinHostPort(target.Desired.Landing.Address, "1080"), Target: peer.Target, ExpectedExit: peer.ExpectedExit}
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entryCertificate, Request: request}}); err != nil {
		t.Fatal(err)
	}
	p := s.nodes[targetCertificate].Checks["entry-a"].Request
	result := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
	if _, err := s.RouteExchange(context.Background(), entryCertificate, &result); err != nil {
		t.Fatal(err)
	}
}

func TestEntryPeerEvidenceIsScopedAndMustPrecedeNewRouteAcceptance(t *testing.T) {
	s := store(t)
	entry := twoPeerEntry(t)
	entryCert, firstCert, secondCert := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	first := artifact(1)
	second, err := NewDesired(landing.Plan{Revision: 1, Address: "100.64.0.9", EgressIP: "192.168.50.3", Sources: []landing.Source{{Address: "100.64.0.3"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		ID, cert string
		desired  Desired
	}{{"landing-example", firstCert, first}, {"landing-other", secondCert, second}} {
		if err := s.Put(Node{ID: target.ID, CertificateID: target.cert, Desired: target.desired, RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
			t.Fatal(err)
		}
		reportRuntime(t, s, target.cert, target.desired)
	}
	if err := s.Put(Node{ID: "entry-a", CertificateID: entryCert, Desired: entry}); err != nil {
		t.Fatal(err)
	}
	accept := func(cert string) RouteAcceptance {
		t.Helper()
		target := s.nodes[cert]
		status, err := s.AcceptLandingRoutes(target.ID, "snapshot-"+target.ID, target.Desired.Revision, target.Desired.ConfigSHA256)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	reportRuntime(t, s, entryCert, entry)
	for _, cert := range []string{firstCert, secondCert} {
		passLandingCheck(t, s, cert, entryCert, entry)
		if status := accept(cert); status.RoutesPassed || status.Reason != "entry-route-unverified" {
			t.Fatal("process-only receipt cleared route warning")
		}
	}
	observation := healthyEntryObservation(entry, time.Now())
	if _, err := s.Exchange(context.Background(), entryCert, &observation); err != nil {
		t.Fatal(err)
	}
	for _, cert := range []string{firstCert, secondCert} {
		passLandingCheck(t, s, cert, entryCert, entry)
		if !accept(cert).RoutesPassed {
			t.Fatal("fresh peer plus independent check rejected")
		}
	}
	blocked := observation.clone()
	blocked.EntryHealth.SampledAt = time.Now()
	peer := blocked.EntryHealth.Peers["landing-example"]
	peer.Status.State, peer.Status.Reason, peer.Status.Stage = "blocked", "business_check_failed", "business_check"
	peer.Status.AllowedUntil = time.Time{}
	blocked.EntryHealth.Peers["landing-example"] = peer
	if _, err := s.Exchange(context.Background(), entryCert, &blocked); err != nil {
		t.Fatal(err)
	}
	if accept(firstCert).RoutesPassed || s.nodes[firstCert].Checks["entry-a"].Result != nil {
		t.Fatal("blocked peer retained old check/success")
	}
	if !accept(secondCert).RoutesPassed || len(s.nodes[secondCert].Checks) == 0 {
		t.Fatal("one peer invalidated unrelated landing")
	}
	recovered := healthyEntryObservation(entry, time.Now())
	if _, err := s.Exchange(context.Background(), entryCert, &recovered); err != nil {
		t.Fatal(err)
	}
	if status := accept(firstCert); status.RoutesPassed || status.Reason != "routes-incomplete" {
		t.Fatal("recovery reused pre-failure independent check")
	}
	passLandingCheck(t, s, firstCert, entryCert, entry)
	if !accept(firstCert).RoutesPassed || !accept(secondCert).RoutesPassed {
		t.Fatal("fresh recovery not accepted")
	}
	loaded, err := OpenStore(s.path)
	if err != nil || loaded.nodes[entryCert].Receipt.EntryHealth == nil {
		t.Fatal("observation not durably retained", err)
	}
	// An expired historical observation may be stored, but cannot clear a
	// warning merely because its enclosing process receipt was just received.
	expired := healthyEntryObservation(entry, time.Now().Add(-20*time.Second))
	expired.EntryHealth.SampledAt = time.Now()
	if _, err := s.Exchange(context.Background(), entryCert, &expired); err != nil {
		t.Fatal(err)
	}
	if accept(firstCert).RoutesPassed || accept(secondCert).RoutesPassed {
		t.Fatal("expired kernel leases accepted")
	}
}

func TestEntryObservationRejectsPartialForeignAndUnboundedProof(t *testing.T) {
	d := twoPeerEntry(t)
	for _, fault := range []string{"none", "subset", "source", "identity", "revision", "exit", "relay", "lease", "no-tcp", "udp", "timestamps", "stage"} {
		t.Run(fault, func(t *testing.T) {
			o := healthyEntryObservation(d, time.Now())
			p := o.EntryHealth.Peers["landing-example"]
			switch fault {
			case "subset":
				delete(o.EntryHealth.Peers, "landing-other")
			case "source":
				o.EntryHealth.Source.PublicKey = "nodekey:foreign"
			case "identity":
				p.Identity.PublicKey = "nodekey:foreign"
			case "revision":
				p.Status.Revision++
			case "exit":
				p.Status.ExitIP = "9.9.9.9"
			case "relay":
				p.Status.LinkState = "derp"
			case "lease":
				p.Status.AllowedUntil = p.Status.StartedAt.Add(time.Hour)
			case "no-tcp":
				p.Status.TCP = false
			case "udp":
				p.Status.UDP = true
			case "timestamps":
				p.Status.CheckedAt = p.Status.StartedAt.Add(-time.Second)
			case "stage":
				p.Status.Stage = "listening-only"
			}
			o.EntryHealth.Peers["landing-example"] = p
			if (validateEntryHealth(d, o.EntryHealth) == nil) != (fault == "none") {
				t.Fatal("invalid health evidence accepted")
			}
		})
	}
	o := healthyEntryObservation(d, time.Now())
	copy := o.clone()
	copy.EntryHealth.Source.PublicKey = "changed"
	delete(copy.EntryHealth.Peers, "landing-other")
	if o.EntryHealth.Source.PublicKey == copy.EntryHealth.Source.PublicKey || len(o.EntryHealth.Peers) != 2 {
		t.Fatal("observation snapshot aliases caller")
	}
}

func TestEntryObservationUsesMutualTLSIdentityAndClearsInvalidPriorProof(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	serverIdentity, _, _ := identity(t, ca, key, true)
	firstIdentity, firstCertificate, _ := identity(t, ca, key, false)
	secondIdentity, secondCertificate, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s := store(t)
	first, second := withRoutedEntry(t, entryArtifact(t, "entry-a", 1)), withRoutedEntry(t, entryArtifact(t, "entry-b", 1))
	for _, n := range []Node{{ID: "entry-a", CertificateID: CertificateID(firstCertificate), Desired: first}, {ID: "entry-b", CertificateID: CertificateID(secondCertificate), Desired: second}} {
		if err := s.Put(n); err != nil {
			t.Fatal(err)
		}
	}
	server, err := NewServer("127.0.0.1:0", s, serverIdentity, roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server.Handler)
	listener.TLS = server.TLSConfig
	listener.StartTLS()
	defer listener.Close()
	newClient := func(certificate tls.Certificate) *Client {
		c, err := NewClient(listener.URL, certificate, roots)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	a, b := newClient(firstIdentity), newClient(secondIdentity)
	firstReport, secondReport := healthyEntryObservation(first, time.Now()), healthyEntryObservation(second, time.Now())
	if _, err := a.Exchange(context.Background(), &firstReport); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Exchange(context.Background(), &secondReport); err != nil {
		t.Fatal(err)
	}
	if s.nodes[CertificateID(firstCertificate)].Receipt.EntryHealth == nil {
		t.Fatal("TLS health extension not delivered")
	}
	if _, err := a.Exchange(context.Background(), &secondReport); err != nil {
		t.Fatal("stale/foreign receipt prevented desired recovery", err)
	}
	if s.nodes[CertificateID(firstCertificate)].Receipt != nil || s.nodes[CertificateID(secondCertificate)].Receipt == nil {
		t.Fatal("one certificate acknowledged another node")
	}
	firstReport = healthyEntryObservation(first, time.Now())
	if _, err := a.Exchange(context.Background(), &firstReport); err != nil {
		t.Fatal(err)
	}
	delete(firstReport.EntryHealth.Peers, "landing-example")
	firstReport.EntryHealth.SampledAt = time.Now()
	got, err := a.Exchange(context.Background(), &firstReport)
	if err != nil || got.Entry.RealityEndpoints[0].EntryID != "entry-a" || s.nodes[CertificateID(firstCertificate)].Receipt.EntryHealth != nil {
		t.Fatal("partial report kept prior peer success or blocked desired delivery", err)
	}
}

func TestEntryObservationCannotReplaySuccessAfterFailure(t *testing.T) {
	s := store(t)
	d := twoPeerEntry(t)
	cert := strings.Repeat("a", 64)
	if err := s.Put(Node{ID: "entry-a", CertificateID: cert, Desired: d}); err != nil {
		t.Fatal(err)
	}
	good := healthyEntryObservation(d, time.Now())
	if _, err := s.Exchange(context.Background(), cert, &good); err != nil {
		t.Fatal(err)
	}
	failed := good.clone()
	failed.EntryHealth.SampledAt = time.Now()
	p := failed.EntryHealth.Peers["landing-example"]
	p.Status.State, p.Status.AllowedUntil = "blocked", time.Time{}
	failed.EntryHealth.Peers["landing-example"] = p
	if _, err := s.Exchange(context.Background(), cert, &failed); err != nil {
		t.Fatal(err)
	}
	reported := s.nodes[cert].ReportedAt
	if _, err := s.Exchange(context.Background(), cert, &good); err != nil {
		t.Fatal(err)
	}
	if s.nodes[cert].Receipt.EntryHealth.Peers["landing-example"].Status.State != "blocked" || !s.nodes[cert].ReportedAt.Equal(reported) {
		t.Fatal("replay replaced newer failure or renewed freshness")
	}
	// Clearing a missing report also fences all older success snapshots.
	if _, err := s.Exchange(context.Background(), cert, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(context.Background(), cert, &good); err != nil {
		t.Fatal(err)
	}
	if s.nodes[cert].Receipt != nil {
		t.Fatal("replay restored cleared receipt")
	}
	future := healthyEntryObservation(d, time.Now().Add(time.Hour))
	if _, err := s.Exchange(context.Background(), cert, &future); err != nil {
		t.Fatal(err)
	}
	if s.nodes[cert].Receipt.EntryHealth != nil || s.nodes[cert].EntryHealthBarrierAt.After(time.Now()) {
		t.Fatal("future snapshot accepted or poisoned watermark")
	}
	fresh := healthyEntryObservation(d, time.Now())
	if _, err := s.Exchange(context.Background(), cert, &fresh); err != nil {
		t.Fatal(err)
	}
	if s.nodes[cert].Receipt.EntryHealth == nil {
		t.Fatal("fresh recovery rejected")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Exchange(context.Background(), cert, &good); err != nil {
		t.Fatal(err)
	}
	if !loaded.nodes[cert].Receipt.EntryHealth.SampledAt.Equal(fresh.EntryHealth.SampledAt) {
		t.Fatal("reopen lost replay barrier")
	}
}

func TestEntryHealthChangeKeepsOtherEntryProofOnSharedLanding(t *testing.T) {
	s := store(t)
	entryCert, otherCert, targetCert := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	d := withRoutedEntry(t, entryArtifact(t, "entry-a", 1))
	target, err := NewDesired(landing.Plan{Revision: 1, Address: "100.64.0.2", EgressIP: "192.168.50.2", Sources: []landing.Source{{Address: "100.64.0.3"}, {Address: "100.64.0.4"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "landing-example", CertificateID: targetCert, Desired: target, RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: entryCert, Address: "100.64.0.3"}, "entry-b": {CertificateID: otherCert, Address: "100.64.0.4"}}}); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, targetCert, target)
	if err := s.Put(Node{ID: "entry-a", CertificateID: entryCert, Desired: d}); err != nil {
		t.Fatal(err)
	}
	good := healthyEntryObservation(d, time.Now())
	if _, err := s.Exchange(context.Background(), entryCert, &good); err != nil {
		t.Fatal(err)
	}
	peer := d.EntryNetwork.Peers[0]
	checks := []RouteCheck{}
	for id, cert := range map[string]string{"entry-a": entryCert, "entry-b": otherCert} {
		checks = append(checks, RouteCheck{CertificateID: cert, Request: RouteProbe{SnapshotID: "shared-snapshot", EntryID: id, LandingID: "landing-example", Revision: 1, ConfigSHA256: target.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: peer.Target, ExpectedExit: peer.ExpectedExit}})
	}
	if err := s.AssignRouteChecks(checks); err != nil {
		t.Fatal(err)
	}
	var stale RouteProbeResult
	for id, cert := range map[string]string{"entry-a": entryCert, "entry-b": otherCert} {
		p := s.nodes[targetCert].Checks[id].Request
		r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: id, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
		if _, err := s.RouteExchange(context.Background(), cert, &r); err != nil {
			t.Fatal(err)
		}
		if id == "entry-a" {
			stale = r
		}
	}
	unaffected := s.nodes[targetCert].Checks["entry-b"]
	failed := good.clone()
	failed.EntryHealth.SampledAt = time.Now()
	p := failed.EntryHealth.Peers["landing-example"]
	p.Status.State = "blocked"
	p.Status.AllowedUntil = time.Time{}
	failed.EntryHealth.Peers["landing-example"] = p
	if _, err := s.Exchange(context.Background(), entryCert, &failed); err != nil {
		t.Fatal(err)
	}
	current := s.nodes[targetCert].Checks
	if len(current) != 2 || current["entry-a"].Result != nil || current["entry-a"].Request.AttemptID == stale.AttemptID || current["entry-b"].Result == nil || current["entry-b"].Request.AttemptID != unaffected.Request.AttemptID || !current["entry-b"].ReceivedAt.Equal(unaffected.ReceivedAt) {
		t.Fatal("health change destroyed inventory or unrelated proof")
	}
	if _, err := s.RouteExchange(context.Background(), entryCert, &stale); err == nil {
		t.Fatal("old in-flight proof accepted")
	}
	if _, err := OpenStore(s.path); err != nil {
		t.Fatal("scoped invalidation persisted invalid state", err)
	}
}
