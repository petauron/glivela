package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func prunableEntryFixture(t *testing.T) (*Store, RetireLandingChange) {
	t.Helper()
	s, d, cert, _ := subscriptionFixture(t, false)
	next := s.business.material
	next.Endpoints = append([]glivela.ImportEndpoint(nil), next.Endpoints...)
	next.Endpoints[0].Retired = true
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		t.Fatal(err)
	}
	other := Node{ID: "surviving-landing", CertificateID: strings.Repeat("c", 64), Desired: artifact(1)}
	if err := s.Put(other); err != nil {
		t.Fatal(err)
	}
	return s, RetireLandingChange{ID: "entry-example", CertificateID: cert, ExpectedRevision: d.Revision, Confirmation: "entry-example", ConfirmHostReturned: true, ExpectedAvailabilityRevision: s.availability.Revision}
}

func TestPruneRetiredEntryPreservesLedgerAndSurvivingNodes(t *testing.T) {
	s, change := prunableEntryFixture(t)
	before := s.business.material
	nodes := maps.Clone(s.nodes)
	names := subscriptionPresentation{Version: 1, Names: map[string]string{change.ID: "Historical name"}}
	raw, _ := json.Marshal(names)
	if err := replacePrivate(filepath.Dir(s.path), subscriptionNamesFile, raw); err != nil {
		t.Fatal(err)
	}
	s.subscriptionNames = names.Names
	if err := s.RetireReturnedEntry(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	after := s.business.material
	if len(after.Endpoints) != 0 || len(after.PrunedEntries) != 1 || len(s.nodes) != len(nodes)-1 {
		t.Fatal("execution configuration not pruned")
	}
	if !reflect.DeepEqual(before.Plan, after.Plan) || !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.References, after.References) || !bytes.Equal(before.RetainedSource, after.RetainedSource) {
		t.Fatal("history or identity changed")
	}
	for cert, n := range nodes {
		if cert != change.CertificateID && !reflect.DeepEqual(n, s.nodes[cert]) {
			t.Fatal("unrelated runtime changed")
		}
	}
	committed := businessBytes(t, s)
	if err := s.RetireReturnedEntry(context.Background(), change); err != nil || !bytes.Equal(committed, businessBytes(t, s)) {
		t.Fatal("retry is not idempotent", err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.business.material, after) || len(loaded.Business().Endpoints) != 0 {
		t.Fatal("restart lost archive")
	}
	old := nodes[change.CertificateID]
	if loaded.Put(old) == nil {
		t.Fatal("retired identity re-enrolled")
	}
	old.ID = "different-entry"
	if loaded.Put(old) == nil {
		t.Fatal("retired certificate reused")
	}
	if _, err := loaded.Exchange(context.Background(), change.CertificateID, nil); err == nil {
		t.Fatal("retired certificate authenticated")
	}
	if err := loaded.BackupController(time.Now()); err != nil {
		t.Fatal("cleanup broke official backup", err)
	}
}

func TestPruneRetiredEntryRejectsUnsafeRequests(t *testing.T) {
	for _, variant := range []string{"active", "online", "identity", "revision", "confirmation", "dependency"} {
		t.Run(variant, func(t *testing.T) {
			s, c := prunableEntryFixture(t)
			switch variant {
			case "active":
				s.business.material.Endpoints[0].Retired = false
			case "online":
				n := s.nodes[c.CertificateID]
				n.ReportedAt = time.Now()
				s.nodes[c.CertificateID] = n
			case "identity":
				c.CertificateID = strings.Repeat("d", 64)
			case "revision":
				c.ExpectedRevision++
			case "confirmation":
				c.Confirmation = "other"
			case "dependency":
				s.business.material.ClientLandings = map[string]glivela.ClientLanding{c.ID: {}}
			}
			nodes := maps.Clone(s.nodes)
			raw := businessBytes(t, s)
			if s.RetireReturnedEntry(context.Background(), c) == nil {
				t.Fatal("unsafe cleanup accepted")
			}
			if !reflect.DeepEqual(nodes, s.nodes) || !bytes.Equal(raw, businessBytes(t, s)) {
				t.Fatal("refusal changed state")
			}
		})
	}
}

func TestPruneRetiredEntryRecoversPartialProjectionWrite(t *testing.T) {
	s, c := prunableEntryFixture(t)
	original := s.business.material.Plan
	saved := s.path + ".fixture-saved"
	if err := os.Rename(s.path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.path, 0700); err != nil {
		t.Fatal(err)
	}
	if s.RetireReturnedEntry(context.Background(), c) == nil {
		t.Fatal("failed projection reported success")
	}
	committed := businessBytes(t, s)
	if len(s.business.material.PrunedEntries) != 1 {
		t.Fatal("revocation not persisted first")
	}
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, s.path); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if _, found := loaded.nodes[c.CertificateID]; found {
		t.Fatal("stale runtime resurrected")
	}
	if !reflect.DeepEqual(original, loaded.business.material.Plan) || !bytes.Equal(committed, businessBytes(t, loaded)) {
		t.Fatal("recovery rewrote history")
	}
	if err := loaded.RetireReturnedEntry(context.Background(), c); err != nil {
		t.Fatal("retry failed", err)
	}
}

func TestPruneRetiredEntryHTTPRequiresAdministrator(t *testing.T) {
	s, c := prunableEntryFixture(t)
	_, ca, key := identity(t, nil, nil, false)
	_, adminCert, _ := identity(t, ca, key, false)
	_, nodeCert, _ := identity(t, ca, key, false)
	h, err := controllerHandler(s, []string{CertificateID(adminCert)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	for _, v := range []struct {
		cert *x509.Certificate
		want int
	}{{nil, 401}, {nodeCert, 403}, {adminCert, 200}} {
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/retire-returned-entry", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if v.cert != nil {
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{v.cert}, VerifiedChains: [][]*x509.Certificate{{v.cert, ca}}}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != v.want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestPruneRetiredEntryPreservesDeferredSourceInventory(t *testing.T) {
	s, d, cert, landingCert := subscriptionFixture(t, true)
	if err := s.SetAvailability("entry-example", "maintenance", time.Time{}, s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	next := s.business.material
	next.Endpoints = append([]glivela.ImportEndpoint(nil), next.Endpoints...)
	next.Endpoints[0].Retired = true
	accounts := append([]glivela.ImportAccount(nil), next.Plan.Accounts...)
	for i := range accounts {
		accounts[i].Grants = append([]glivela.RouteGrant(nil), accounts[i].Grants...)
		for j := range accounts[i].Grants {
			accounts[i].Grants[j].Enabled = false
		}
	}
	var err error
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[landingCert]
	c := RetireLandingChange{ID: "entry-example", CertificateID: cert, ExpectedRevision: d.Revision, ExpectedAvailabilityRevision: s.availability.Revision, Confirmation: "entry-example", ConfirmHostReturned: true}
	if err := s.RetireReturnedEntry(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, s.nodes[landingCert]) {
		t.Fatal("retained landing policy or proof changed")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if !loaded.deferredEntries(loaded.nodes[landingCert], time.Now())[c.ID] {
		t.Fatal("historical verifier became active again")
	}
}
