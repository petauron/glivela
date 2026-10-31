package control

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

func entryArtifact(t *testing.T, id string, revision uint64) Desired {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	protocolID := uuid.NewString()
	plan := glivela.XrayPlan{Revision: revision,
		RealityEndpoints: []glivela.RealityEndpoint{{ID: id + "-endpoint", EntryID: id, InboundTag: id + "-inbound", ListenAddress: "100.64.0.3", ListenPort: 10443, AdvertiseHost: id + ".example.test", AdvertisePort: 443, Target: "www.example.com:443", ServerNames: []string{"www.example.com"}, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortIDs: []string{"abcd"}, Fingerprint: "chrome"}},
		Credentials:      []glivela.CredentialMaterial{{Credential: glivela.Credential{ID: id + "-native", AccountID: "account-example", Kind: glivela.NativeCredential, User: id + "-user", Identity: glivela.Identity(protocolID), EntryID: id, Enabled: true}, ProtocolID: protocolID}},
	}
	desired, err := NewEntryDesired(plan, EntryNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	return desired
}

func TestEntryDesiredBindsExactRoleIdentityAndKeyPair(t *testing.T) {
	for _, fault := range []string{"no-role", "both-roles", "revision", "credential", "other-entry", "public-key", "multiple-entries", "policy"} {
		t.Run(fault, func(t *testing.T) {
			d := entryArtifact(t, "entry-example", 1)
			switch fault {
			case "no-role":
				d.Entry = nil
			case "both-roles":
				d.Landing = artifact(1).Landing
			case "revision":
				d.Entry.Revision++
			case "credential":
				d.Entry.Credentials[0].ProtocolID = uuid.NewString()
			case "other-entry":
				d.Entry.Credentials[0].Credential.EntryID = "other-entry"
			case "public-key":
				d.Entry.RealityEndpoints[0].PublicKey = entryArtifact(t, "other-entry", 1).Entry.RealityEndpoints[0].PublicKey
			case "multiple-entries":
				d.Entry.RealityEndpoints = append(d.Entry.RealityEndpoints, entryArtifact(t, "other-entry", 1).Entry.RealityEndpoints[0])
			case "policy":
				d.Entry.NativeEgress = glivela.EgressPolicy("unknown")
			}
			if d.Validate() == nil {
				t.Fatal("changed entry role/identity/configuration accepted")
			}
		})
	}
	d := entryArtifact(t, "entry-example", 1)
	copy := d.clone()
	copy.Config[0] = 'x'
	copy.Entry.Credentials[0].ProtocolID = "changed"
	copy.Entry.RealityEndpoints[0].ServerNames[0] = "changed.example.test"
	copy.Entry.RealityEndpoints[0].ShortIDs[0] = "ffff"
	if d.Validate() != nil {
		t.Fatal("clone altered original entry configuration")
	}
	input := *d.Entry
	wanted, err := NewEntryDesired(input, *d.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	input.RealityEndpoints[0].ServerNames[0] = "different.example.test"
	if wanted.Validate() != nil {
		t.Fatal("desired state aliases caller-owned plan")
	}
}

func TestLandingDriverCannotExecuteOrStopEntryRole(t *testing.T) {
	d := entryArtifact(t, "entry-example", 1)
	driver := SystemdDriver{}
	ctx := context.Background()
	for _, err := range []error{driver.Validate(ctx, d, "/unused/config.json"), driver.Activate(ctx, d, nil), driver.Activate(ctx, artifact(1), &d), driver.Stop(ctx, d), driver.Healthy(ctx, d)} {
		if err == nil || !strings.Contains(err.Error(), "role") && !strings.Contains(err.Error(), "landing") {
			t.Fatal("entry reached native landing service operations", err)
		}
	}
}

func TestEntryEnrollmentPreservesIdentityAndRevokesOldVerifier(t *testing.T) {
	s := store(t)
	entry := entryArtifact(t, "entry-example", 1)
	certificate, rotated := strings.Repeat("b", 64), strings.Repeat("c", 64)
	landingCertificate := strings.Repeat("a", 64)
	landingNode := Node{ID: "landing-example", CertificateID: landingCertificate, Desired: artifact(1), RouteEntries: map[string]RouteEntry{"entry-example": {CertificateID: certificate, Address: "100.64.0.3"}}}
	if err := s.Put(landingNode); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "wrong-entry", CertificateID: certificate, Desired: entry}); err == nil {
		t.Fatal("entry application identity was not enforced")
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: certificate, Desired: entry}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: certificate, Desired: artifact(2)}); err == nil {
		t.Fatal("entry silently became a landing")
	}
	if err := s.Put(Node{ID: "another-landing", CertificateID: certificate, Desired: artifact(1)}); err == nil {
		t.Fatal("entry/verifier certificate became a different landing")
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: rotated, Desired: entry}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(context.Background(), certificate, nil); err == nil {
		t.Fatal("old entry certificate retained configuration access")
	}
	if s.nodes[landingCertificate].RouteEntries["entry-example"].CertificateID != rotated {
		t.Fatal("verifier identity was not rotated atomically")
	}
	loaded, err := OpenStore(s.path)
	if err != nil || loaded.nodes[rotated].ID != "entry-example" || loaded.nodes[rotated].Desired.Entry == nil {
		t.Fatal("entry identity/configuration lost across restart", err)
	}
	if _, err := loaded.AcceptLandingRoutes("entry-example", "snapshot-example", 1, entry.ConfigSHA256); err == nil {
		t.Fatal("entry enrollment was treated as landing acceptance")
	}
}

func TestEntryUpdatesAndReadinessCannotReuseOldRouteProof(t *testing.T) {
	s := store(t)
	landing, entry := artifact(1), withRoutedEntry(t, entryArtifact(t, "entry-a", 1))
	landingCert, entryCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := s.Put(Node{ID: "landing-example", CertificateID: landingCert, Desired: landing, RouteEntries: map[string]RouteEntry{"entry-a": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, landingCert, landing)
	check := RouteProbe{SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-example", Revision: 1, ConfigSHA256: landing.ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: entry.EntryNetwork.Peers[0].Target, ExpectedExit: entry.EntryNetwork.Peers[0].ExpectedExit}
	verify := func() {
		t.Helper()
		if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entryCert, Request: check}}); err != nil {
			t.Fatal(err)
		}
		p := s.nodes[landingCert].Checks["entry-a"].Request
		result := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
		if _, err := s.RouteExchange(context.Background(), entryCert, &result); err != nil {
			t.Fatal(err)
		}
	}
	verify()
	if err := s.Put(Node{ID: "entry-a", CertificateID: entryCert, Desired: entry}); err != nil {
		t.Fatal(err)
	}
	// Diagnostics may observe the real route while entry deployment is still
	// unverified. That observation alone must never clear the runtime warning.
	verify()
	status, err := s.AcceptLandingRoutes("landing-example", "snapshot-a", 1, landing.ConfigSHA256)
	if err != nil || status.RoutesPassed || status.Reason != "entry-runtime-unverified" {
		t.Fatal("route observation replaced entry runtime proof", err)
	}
	reportRuntime(t, s, entryCert, entry)
	if s.nodes[landingCert].Checks["entry-a"].Result != nil {
		t.Fatal("first entry runtime proof reused pre-application route results")
	}
	verify()
	status, err = s.AcceptLandingRoutes("landing-example", "snapshot-a", 1, landing.ConfigSHA256)
	if err != nil || status.RoutesPassed || status.Reason != "entry-route-unverified" {
		t.Fatal("process receipt replaced peer gate evidence", err)
	}
	observation := healthyEntryObservation(entry, time.Now())
	if _, err := s.Exchange(context.Background(), entryCert, &observation); err != nil {
		t.Fatal(err)
	}
	verify()
	status, err = s.AcceptLandingRoutes("landing-example", "snapshot-a", 1, landing.ConfigSHA256)
	if err != nil || !status.RoutesPassed {
		t.Fatal("fresh applied entry and new route proof not accepted", err)
	}
	_, err = s.Exchange(context.Background(), entryCert, nil)
	if err != nil || s.nodes[landingCert].Checks["entry-a"].Result != nil {
		t.Fatal("lost entry readiness retained old success", err)
	}
	plan := entry.clone().Entry
	plan.Revision++
	next, err := NewEntryDesired(*plan, *entry.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "entry-a", CertificateID: entryCert, Desired: next}); err != nil {
		t.Fatal(err)
	}
	if len(s.nodes[landingCert].Checks) != 0 {
		t.Fatal("entry update retained route proof for the previous configuration")
	}
}
