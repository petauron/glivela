package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func artifact(revision uint64) Desired {
	d, err := NewDesired(landing.Plan{Revision: revision, Address: "100.64.0.2", EgressIP: "192.168.50.2", Sources: []landing.Source{{Address: "100.64.0.3"}}})
	if err != nil {
		panic(err)
	}
	return d
}

func identity(t *testing.T, ca *x509.Certificate, signer *ecdsa.PrivateKey, server bool) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if ca == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
		ca = template
		signer = key
	} else if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert, key
}

func store(t *testing.T) *Store {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDirectMutualTLSIsolation(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	server, _, _ := identity(t, ca, key, true)
	first, cert, _ := identity(t, ca, key, false)
	second, _, _ := identity(t, ca, key, false)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s := store(t)
	if err := s.Put(Node{ID: "landing-a", CertificateID: CertificateID(cert), Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(Handler(s))
	var err error
	listener.TLS, err = ServerTLS(server, pool)
	if err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	defer listener.Close()
	client, err := NewClient(listener.URL, first, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	desired, err := client.Exchange(context.Background(), nil)
	if err != nil || desired.Revision != 1 {
		t.Fatalf("exchange: %v", err)
	}
	unknown, err := NewClient(listener.URL, second, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer unknown.Close()
	if _, err = unknown.Exchange(context.Background(), nil); err == nil {
		t.Fatal("unenrolled certificate accepted")
	}
	report := Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: 1, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}}
	if _, err = client.Exchange(context.Background(), &report); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(s.path)
	if err != nil || reloaded.nodes[CertificateID(cert)].Receipt == nil {
		t.Fatalf("receipt not durable: %v", err)
	}
	report.RuntimeReady = false
	if _, err = client.Exchange(context.Background(), &report); err != nil {
		t.Fatal(err)
	}
	if s.nodes[CertificateID(cert)].Receipt != nil {
		t.Fatal("failed runtime still ready")
	}
	// A different CA cannot impersonate the controller.
	_, wrong, _ := identity(t, nil, nil, false)
	wrongPool := x509.NewCertPool()
	wrongPool.AddCert(wrong)
	badClient, err := NewClient(listener.URL, first, wrongPool)
	if err != nil {
		t.Fatal(err)
	}
	defer badClient.Close()
	if _, err = badClient.Exchange(context.Background(), nil); err == nil {
		t.Fatal("untrusted controller accepted")
	}
}

func TestEnrollmentRevisionAndRotation(t *testing.T) {
	s := store(t)
	_, ca, key := identity(t, nil, nil, false)
	_, a, _ := identity(t, ca, key, false)
	_, b, _ := identity(t, ca, key, false)
	node := Node{ID: "stable-node", CertificateID: CertificateID(a), Desired: artifact(2)}
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	old := node
	old.Desired = artifact(1)
	if s.Put(old) == nil {
		t.Fatal("rollback accepted")
	}
	node.CertificateID = CertificateID(b)
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(context.Background(), CertificateID(a), nil); err == nil {
		t.Fatal("rotated identity still authorized")
	}
	stale := Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: 1, ConfigSHA256: node.Desired.ConfigSHA256, RuntimeReady: true}}
	desired, err := s.Exchange(context.Background(), CertificateID(b), &stale)
	if err != nil || desired.Revision != 2 || s.nodes[CertificateID(b)].Receipt != nil {
		t.Fatal("stale receipt accepted or update blocked")
	}
}

type fakeRuntime struct {
	current              Observation
	inspectErr, applyErr error
	applies              int
}

func (f *fakeRuntime) Inspect(context.Context) (Observation, error) {
	return f.current, f.inspectErr
}
func (f *fakeRuntime) Apply(_ context.Context, desired Desired) error {
	f.applies++
	if f.applyErr != nil {
		return f.applyErr
	}
	f.current = Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: desired.Revision, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}}
	f.inspectErr = nil
	return nil
}

type fakeClient struct {
	desired Desired
	err     error
	reports int
}

func (f *fakeClient) Exchange(_ context.Context, receipt *Observation) (Desired, error) {
	if receipt != nil {
		f.reports++
	}
	return f.desired, f.err
}

func TestNodeReconcileAndOfflinePreservation(t *testing.T) {
	runtime := &fakeRuntime{inspectErr: os.ErrNotExist}
	client := &fakeClient{desired: artifact(1)}
	node := NodeRunner{Client: client, Runtime: runtime}
	if err := node.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := node.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.applies != 1 {
		t.Fatal("unchanged revision reapplied")
	}
	client.err = errors.New("offline")
	if node.Step(context.Background()) == nil || runtime.applies != 1 {
		t.Fatal("offline changed runtime")
	}
	client.err = nil
	runtime.current.RuntimeReady = false
	if node.Step(context.Background()) == nil || runtime.applies != 1 {
		t.Fatal("health failure restarted service")
	}
	runtime.inspectErr = errors.New("unreadable state")
	if node.Step(context.Background()) == nil || runtime.applies != 1 {
		t.Fatal("unknown state overwritten")
	}
}

func TestStoreRefusesUnsafeFiles(t *testing.T) {
	s := store(t)
	if err := os.WriteFile(s.path, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(s.path); err == nil {
		t.Fatal("public state accepted")
	}
}

func TestNewObservationInvalidatesPreviousSuccess(t *testing.T) {
	for _, kind := range []string{"missing", "stale", "wrong-digest", "unhealthy"} {
		t.Run(kind, func(t *testing.T) {
			s := store(t)
			_, ca, key := identity(t, nil, nil, false)
			_, cert, _ := identity(t, ca, key, false)
			id := CertificateID(cert)
			desired := artifact(2)
			if err := s.Put(Node{ID: "one", CertificateID: id, Desired: desired}); err != nil {
				t.Fatal(err)
			}
			report := Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: 2, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}}
			if _, err := s.Exchange(context.Background(), id, &report); err != nil || s.nodes[id].Receipt == nil {
				t.Fatal("initial success not recorded", err)
			}
			observation := &report
			switch kind {
			case "missing":
				observation = nil
			case "stale":
				report.Revision = 1
			case "wrong-digest":
				report.ConfigSHA256 = strings.Repeat("0", 64)
			case "unhealthy":
				report.RuntimeReady = false
			}
			got, err := s.Exchange(context.Background(), id, observation)
			if err != nil || got.Revision != 2 || s.nodes[id].Receipt != nil {
				t.Fatal("old success retained or reconciliation blocked", err)
			}
			reopened, err := OpenStore(s.path)
			if err != nil || reopened.nodes[id].Receipt != nil || reopened.nodes[id].ReportedAt.IsZero() {
				t.Fatal("health invalidation not durable", err)
			}
		})
	}
}

func TestHandlerRejectsMalformedAndUnauthenticatedRequests(t *testing.T) {
	s := store(t)
	handler := Handler(s)
	request := httptest.NewRequest(http.MethodPost, "/v1/exchange", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated request accepted")
	}
	_, ca, key := identity(t, nil, nil, false)
	_, cert, _ := identity(t, ca, key, false)
	if err := s.Put(Node{ID: "one", CertificateID: CertificateID(cert), Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"node":"other"}`, `{} {}`, `{"receipt":`, strings.Repeat(" ", maxMessage) + `{}`} {
		request = httptest.NewRequest(http.MethodPost, "/v1/exchange", strings.NewReader(body))
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, ca}}}
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("malformed request: %d", response.Code)
		}
	}
}

func TestFailedApplicationCannotReportReady(t *testing.T) {
	runtime := &fakeRuntime{inspectErr: os.ErrNotExist, applyErr: errors.New("validation failed")}
	client := &fakeClient{desired: artifact(1)}
	if (NodeRunner{Client: client, Runtime: runtime}).Step(context.Background()) == nil {
		t.Fatal("apply failure ignored")
	}
	if client.reports != 0 {
		t.Fatal("failed application reported")
	}
}

func TestStateUpdateIsTransactional(t *testing.T) {
	s := store(t)
	_, ca, key := identity(t, nil, nil, false)
	_, cert, _ := identity(t, ca, key, false)
	node := Node{ID: "one", CertificateID: CertificateID(cert), Desired: artifact(1)}
	if err := s.Put(node); err != nil {
		t.Fatal(err)
	}
	// Simulate storage becoming unavailable without modifying the old file.
	s.path = filepath.Join(filepath.Dir(s.path), "absent", "state.json")
	node.Desired = artifact(2)
	if s.Put(node) == nil {
		t.Fatal("failed persistence accepted")
	}
	if s.nodes[node.CertificateID].Desired.Revision != 1 {
		t.Fatal("memory advanced without durable state")
	}
}
