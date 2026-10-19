package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

// A real encrypted handover and controller load, with synthetic runtime
// observations. This does not prove actual Docker or public inbound traffic.
func subscriptionFixture(t *testing.T, routed bool, decoyTarget ...string) (*Store, Desired, string, string) {
	t.Helper()
	d := entryArtifact(t, "entry-example", 1)
	if routed {
		d = withRoutedEntry(t, d)
	}
	if len(decoyTarget) > 0 {
		plan := *d.clone().Entry
		plan.RealityEndpoints[0].Target = decoyTarget[0]
		plan.RealityEndpoints[0].ServerNames = []string{"example.com"}
		var err error
		d, err = NewEntryDesired(plan, *d.EntryNetwork)
		if err != nil {
			t.Fatal(err)
		}
	}
	m := dataImportFixture(t)
	m.Endpoints[0].Reality = d.Entry.RealityEndpoints[0]
	m.Endpoints[0].QuotaAppliedEnabled = true
	m.Plan.Accounts[0].Credentials = nil
	m.Plan.Accounts[0].Usage = nil
	m.Plan.Accounts[0].Grants = d.Entry.Grants
	m.Plan.Accounts[0].Account.Plan.TotalBytes = 10000
	m.Plan.Accounts[0].Account.Plan.ExpiryTime = time.Now().Add(24 * time.Hour).UnixMilli()
	m.ProtocolSecrets = map[string]string{}
	m.TrafficCounters = map[string]glivela.ImportTrafficCounters{}
	for _, material := range d.Entry.Credentials {
		m.Plan.Accounts[0].Credentials = append(m.Plan.Accounts[0].Credentials, material.Credential)
		m.Plan.Accounts[0].Usage = append(m.Plan.Accounts[0].Usage, glivela.UsageMember{CredentialID: material.Credential.ID, Baseline: 100, Observed: 500, Active: true})
		m.ProtocolSecrets[material.Credential.ID] = material.ProtocolID
		m.TrafficCounters[material.Credential.ID] = glivela.ImportTrafficCounters{UploadBytes: 300, DownloadBytes: 400, RawUploadBytes: 500, RawDownloadBytes: 600}
	}
	// A second real account shares the entry but never the subscription token,
	// protocol identity or ledger. Both are encrypted in the owned checkpoint.
	otherSecret := "22222222-2222-4222-8222-222222222222"
	other := glivela.Credential{ID: "credential-other", AccountID: "account-other", EntryID: "entry-example", Kind: glivela.NativeCredential, User: "other", Identity: glivela.Identity(otherSecret), Enabled: true}
	otherAccount := glivela.ImportAccount{Account: glivela.Account{ID: other.AccountID, DisplayName: "Other", Plan: glivela.AccountPlan{Enabled: true, TotalBytes: 20000}, DesiredRevision: 1, AppliedRevision: 1}, SubscriptionTokenFingerprint: glivela.SubscriptionTokenFingerprint("other-token"), Credentials: []glivela.Credential{other}, Usage: []glivela.UsageMember{{CredentialID: other.ID, Baseline: 100, Observed: 900, Active: true}}}
	m.Plan.Accounts = append(m.Plan.Accounts, otherAccount)
	m.SubscriptionTokens[other.AccountID] = "other-token"
	m.ResetSchedules[other.AccountID] = glivela.ImportResetSchedule{}
	m.ProtocolSecrets[other.ID] = otherSecret
	m.TrafficCounters[other.ID] = glivela.ImportTrafficCounters{UploadBytes: 600, DownloadBytes: 700}
	plan := *d.Entry
	plan.Credentials = append(plan.Credentials, glivela.CredentialMaterial{Credential: other, ProtocolID: otherSecret})
	var err error
	d, err = NewEntryDesired(plan, *d.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if routed {
		m.References.Nodes["landing-example"] = glivela.ImportNode{Name: "Example landing", PreviousStatus: "active"}
	}
	return ownedSubscriptionFixture(t, m, d, routed)
}

func ownedSubscriptionFixture(t *testing.T, m glivela.ImportMaterial, d Desired, routed bool) (*Store, Desired, string, string) {
	t.Helper()
	s := store(t)
	dir := filepath.Dir(s.path)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	m.Plan, err = glivela.PlanImport(m.Plan.Accounts)
	if err != nil {
		t.Fatal(err)
	}
	transfer, storage := bytes.Repeat([]byte{31}, 32), bytes.Repeat([]byte{32}, 32)
	sealed, err := glivela.SealImportMaterial(m, transfer, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if err := StageImport(dir, "snapshot-example", sealed, transfer, storage); err != nil {
		t.Fatal(err)
	}
	if err := AdoptStagedBusiness(dir, "snapshot-example", ownershipFixture(m), storage); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "business.key")
	if err := os.WriteFile(key, storage, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadBusiness(key); err != nil {
		t.Fatal(err)
	}
	entryCert, landingCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := s.Put(Node{ID: d.Entry.RealityEndpoints[0].EntryID, CertificateID: entryCert, Desired: d}); err != nil {
		t.Fatal(err)
	}
	if routed {
		if err := s.Put(Node{ID: "landing-example", CertificateID: landingCert, Desired: artifact(1), RouteEntries: map[string]RouteEntry{"entry-example": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
			t.Fatal(err)
		}
	}
	return s, d, entryCert, landingCert
}

func getSubscription(t *testing.T, s *Store, path, agent string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("User-Agent", agent)
	SubscriptionHandler(s).ServeHTTP(w, r)
	for key, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} {
		if w.Header().Get(key) != want {
			t.Fatal("missing sensitive-response protection", key)
		}
	}
	return w
}

func TestOwnedSubscriptionRetainsIdentityQuotaAndFormats(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	before := s.Business()
	disk, err := os.ReadFile(filepath.Join(filepath.Dir(s.path), "business.json"))
	if err != nil {
		t.Fatal(err)
	}
	if w := getSubscription(t, s, "/sub/example-token", ""); w.Code != 503 {
		t.Fatal("historical health published native entry", w.Code)
	}
	reportRuntime(t, s, cert, d)
	w := getSubscription(t, s, "/sub/example-token", "")
	if w.Code != 200 {
		t.Fatal("verified native unavailable", w.Code, w.Body.String())
	}
	plain, err := base64.StdEncoding.DecodeString(w.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(d.Entry.Credentials[0].ProtocolID)) || !bytes.Contains(plain, []byte(d.Entry.RealityEndpoints[0].AdvertiseHost)) {
		t.Fatal("original credential or endpoint identity changed")
	}
	want := "upload=0; download=400; total=10000; expire=" + strconv.FormatInt(s.business.material.Plan.Accounts[0].Account.Plan.ExpiryTime/1000, 10)
	if w.Header().Get("Subscription-Userinfo") != want {
		t.Fatal("quota header changed", w.Header().Get("Subscription-Userinfo"))
	}
	for _, path := range []string{"/sub/example-token?target=clash", "/sub/example-token?format=mihomo"} {
		w := getSubscription(t, s, path, "")
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "yaml") || strings.Contains(w.Body.String(), "skip-cert-verify: true") {
			t.Fatal("Mihomo format unavailable or certificate verification disabled")
		}
		if !strings.Contains(w.Body.String(), "uuid: "+d.Entry.Credentials[0].ProtocolID) {
			t.Fatal("Mihomo protocol identity changed")
		}
	}
	if w := getSubscription(t, s, "/sub/example-token", "Mihomo"); !strings.Contains(w.Header().Get("Content-Type"), "yaml") {
		t.Fatal("client format detection lost")
	}
	head := httptest.NewRecorder()
	SubscriptionHandler(s).ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/sub/example-token", nil))
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "0" {
		t.Fatal("HEAD did not preserve metadata without body")
	}
	after, err := os.ReadFile(filepath.Join(filepath.Dir(s.path), "business.json"))
	current := s.Business()
	// The explicit node report above changes runtime observations, not business
	// data. Keep the ledger/cycle/source comparison independent of that report.
	before.Runtimes = current.Runtimes
	if err != nil || !bytes.Equal(disk, after) || !reflect.DeepEqual(before, current) {
		t.Fatal("download mutated ledger, cycle or encrypted source", err)
	}
	for _, secret := range []string{"privateKey", d.Entry.RealityEndpoints[0].PrivateKey, "example-token", "synthetic-event"} {
		if bytes.Contains(plain, []byte(secret)) {
			t.Fatal("subscription disclosed server-side secret")
		}
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadBusiness(filepath.Join(filepath.Dir(s.path), "business.key")); err != nil {
		t.Fatal(err)
	}
	if got := getSubscription(t, loaded, "/sub/example-token", ""); got.Code != 200 || got.Body.String() != w.Body.String() {
		t.Fatal("restart changed subscription")
	}
}

func TestOwnedSubscriptionRejectsUnauthorizedUnappliedAndRevoked(t *testing.T) {
	for _, fault := range []string{"unknown-token", "staged-only", "disabled", "expired", "exhausted", "inactive-credential", "stale-runtime", "changed-config", "endpoint-limit", "retired", "credential-missing"} {
		t.Run(fault, func(t *testing.T) {
			s, d, cert, _ := subscriptionFixture(t, false)
			reportRuntime(t, s, cert, d)
			path := "/sub/example-token"
			want := http.StatusServiceUnavailable
			switch fault {
			case "unknown-token":
				path = "/sub/not-the-token"
				want = 404
			case "staged-only":
				s.business.material.Ownership = nil
				want = 404
			case "disabled":
				s.business.material.Plan.Accounts[0].Account.Plan.Enabled = false
				want = 404
			case "expired":
				s.business.material.Plan.Accounts[0].Account.Plan.ExpiryTime = time.Now().Add(-time.Second).UnixMilli()
				want = 404
			case "exhausted":
				s.business.material.Plan.Accounts[0].Account.Plan.TotalBytes = 400
				want = 404
			case "inactive-credential":
				s.business.material.Plan.Accounts[0].Usage[0].Active = false
			case "stale-runtime":
				node := s.nodes[cert]
				node.ReportedAt = time.Now().Add(-2 * time.Minute)
				s.nodes[cert] = node
			case "changed-config":
				s.business.material.Endpoints[0].Reality.AdvertiseHost = "other.example.test"
			case "endpoint-limit":
				s.business.material.Endpoints[0].TotalBytes = 100
				s.business.material.Endpoints[0].UsedBytes = 100
			case "retired":
				s.business.material.Endpoints[0].Retired = true
			case "credential-missing":
				node := s.nodes[cert]
				node.Desired = node.Desired.clone()
				node.Desired.Entry.Credentials = nil
				s.nodes[cert] = node
			}
			w := getSubscription(t, s, path, "")
			if w.Code != want {
				t.Fatal("unsafe subscription published", fault, w.Code, want)
			}
			if strings.Contains(w.Body.String(), d.Entry.Credentials[0].ProtocolID) || w.Header().Get("Subscription-Userinfo") != "" {
				t.Fatal("refused response disclosed credentials or account plan")
			}
		})
	}
	for _, path := range []string{"/sub/example-token?format=invalid", "/sub/example-token?target=clash&target=mihomo", "/sub/example-token?format=%QQ", "/sub/example-token?extra=value", "/v1/admin/business", "/v1/exchange", "/sub/example-token/more"} {
		s, _, _, _ := subscriptionFixture(t, false)
		w := getSubscription(t, s, path, "")
		if w.Code != 400 && w.Code != 404 {
			t.Fatal("unexpected endpoint exposed", path, w.Code)
		}
	}
}

func TestSubscriptionRouteRequiresCurrentPeerAndIndependentCheck(t *testing.T) {
	s, d, entryCert, landingCert := subscriptionFixture(t, true)
	reportRuntime(t, s, entryCert, d)
	reportRuntime(t, s, landingCert, artifact(1))
	routeSecret := d.Entry.Credentials[1].ProtocolID
	assertRoute := func(want bool) {
		t.Helper()
		w := getSubscription(t, s, "/sub/example-token", "")
		plain, err := base64.StdEncoding.DecodeString(w.Body.String())
		if w.Code != 200 || err != nil || bytes.Contains(plain, []byte(routeSecret)) != want {
			t.Fatal("incorrect route availability", w.Code, want)
		}
	}
	assertRoute(false)
	good := healthyEntryObservation(d, time.Now())
	if _, err := s.Exchange(context.Background(), entryCert, &good); err != nil {
		t.Fatal(err)
	}
	assertRoute(false)
	p := RouteProbe{SnapshotID: "snapshot-example", EntryID: "entry-example", LandingID: "landing-example", Revision: 1, ConfigSHA256: artifact(1).ConfigSHA256, SOCKSAddress: "100.64.0.2:1080", Target: d.EntryNetwork.Peers[0].Target, ExpectedExit: d.EntryNetwork.Peers[0].ExpectedExit}
	if err := s.AssignRouteChecks([]RouteCheck{{CertificateID: entryCert, Request: p}}); err != nil {
		t.Fatal(err)
	}
	p = s.nodes[landingCert].Checks["entry-example"].Request
	r := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now(), Passed: true, TLSVerified: true, HTTPStatus: 200, ObservedExit: p.ExpectedExit}
	if _, err := s.RouteExchange(context.Background(), entryCert, &r); err != nil {
		t.Fatal(err)
	}
	assertRoute(true)
	bad := good.clone()
	bad.EntryHealth.SampledAt = time.Now()
	peer := bad.EntryHealth.Peers["landing-example"]
	peer.Status.State = "blocked"
	peer.Status.AllowedUntil = time.Time{}
	bad.EntryHealth.Peers["landing-example"] = peer
	if _, err := s.Exchange(context.Background(), entryCert, &bad); err != nil {
		t.Fatal(err)
	}
	assertRoute(false)
	// HideNative remains policy even when its route is unavailable: never
	// substitute the direct credential for the user's selected double hop.
	s.business.material.Plan.Accounts[0].Grants[0].HideNative = true
	if w := getSubscription(t, s, "/sub/example-token", ""); w.Code != 503 {
		t.Fatal("unverified hidden-native route fell back to direct", w.Code)
	}
}

func TestSubscriptionOriginIsPrivateAndHasNoControlAuthority(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	reportRuntime(t, s, cert, d)
	for _, address := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "8.8.8.8:8080", "localhost:8080"} {
		if _, err := NewSubscriptionServer(address, s); err == nil {
			t.Fatal("public/ambiguous origin allowed", address)
		}
	}
	origin, err := NewSubscriptionServer("127.0.0.1:0", s)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(origin.Handler)
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/sub/example-token")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("token-only client could not download")
	}
	for _, path := range []string{"/v1/admin/business", "/v1/exchange"} {
		response, err := server.Client().Post(server.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 405 {
			t.Fatal("subscription origin exposed control API")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.subscription(ctx, "example-token", false); err == nil {
		t.Fatal("canceled request ignored")
	}
	// Neither a forwarded identity nor an unknown bearer selects an account.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/sub/unknown", nil)
	r.Header.Set("X-Forwarded-User", "account-example")
	SubscriptionHandler(s).ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("forwarded account identity trusted")
	}
}

func TestSubscriptionFixturesRemainValid(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, true)
	if err := s.business.material.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(s.Business()); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionTokensIsolateAccountsOnSharedEntry(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	reportRuntime(t, s, cert, d)
	for _, item := range []struct{ token, secret, other, header string }{{"example-token", d.Entry.Credentials[0].ProtocolID, "22222222-2222-4222-8222-222222222222", "upload=0; download=400; total=10000"}, {"other-token", "22222222-2222-4222-8222-222222222222", d.Entry.Credentials[0].ProtocolID, "upload=0; download=800; total=20000"}} {
		w := getSubscription(t, s, "/sub/"+item.token, "")
		plain, err := base64.StdEncoding.DecodeString(w.Body.String())
		if w.Code != 200 || err != nil || !bytes.Contains(plain, []byte(item.secret)) || bytes.Contains(plain, []byte(item.other)) || !strings.HasPrefix(w.Header().Get("Subscription-Userinfo"), item.header) {
			t.Fatal("shared-entry subscription mixed accounts")
		}
	}
}
