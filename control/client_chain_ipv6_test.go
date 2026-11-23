package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestClientChainsRetiredAndLegacyTombstonesPreserved(t *testing.T) {
	s, entryCert, landingCert, grant := managedServerLandingFixture(t)
	if _, err := s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	_, ca, caKey := identity(t, nil, nil, false)
	_, adminCert, _ := identity(t, ca, caKey, false)
	handler, err := controllerHandler(s, []string{CertificateID(adminCert)})
	if err != nil {
		t.Fatal(err)
	}

	// Retired /v1/admin/client-chains endpoint must return 404 even for administrators.
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/client-chains", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}, VerifiedChains: [][]*x509.Certificate{{adminCert, ca}}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for retired client-chains endpoint, got %d: %s", w.Code, w.Body.String())
	}

	// BusinessInventory must not advertise a clientChains field.
	invRaw, err := json.Marshal(s.Business())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(invRaw), `"clientChains"`) {
		t.Fatalf("retired clientChains field still present in BusinessInventory: %s", invRaw)
	}

	// Seed a persisted pre-retirement ledger with both a deleted tombstone and a legacy
	// enabled ClientChain, a historical display name in subscription-names.json, plus
	// stale SpeedPeers/ClientLinks on entry and a stale client-only listener on landing.
	legacyKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 16))
	tombstone := glivela.ClientChain{
		ID:                   "legacy-tombstone",
		AccountID:            "account-example",
		EntryID:              "entry-example",
		EgressID:             "landing-example",
		Name:                 "Retired IPv6 Chain",
		Port:                 24001,
		Key:                  legacyKey,
		Enabled:              false,
		Transport:            "ipv6-ss2022",
		SourceIPv6:           "2001:4860:4860::8888",
		ServerIPv6:           "2606:4700:4700::1111",
		EntryCertificateID:   entryCert,
		LandingCertificateID: landingCert,
	}
	legacyActive := tombstone
	legacyActive.ID = "legacy-enabled"
	legacyActive.Port = 24002
	legacyActive.Enabled = true
	legacyActive.ServerIPv6 = "2606:4700:4700::1001"

	next := s.business.material
	next.ClientChains = []glivela.ClientChain{tombstone, legacyActive}
	next.DeletedClientChains = map[string]bool{tombstone.ID: true}
	if err = s.saveOwnedBusinessLocked(next); err != nil {
		t.Fatal(err)
	}

	rawNodes := s.copy()
	entry := rawNodes[entryCert]
	entryNet := entry.Desired.EntryNetwork.clone()
	entryNet.SpeedPeers = []EntrySpeedPeer{{ChainID: legacyActive.ID, AccountID: legacyActive.AccountID, LandingID: legacyActive.EgressID, Address: legacyActive.ServerIPv6, Source: legacyActive.SourceIPv6}}
	entryPlan := *entry.Desired.clone().Entry
	entryPlan.Revision++
	entryPlan.ClientLinks = []glivela.PrivateClientPolicy{{
		PrivateClientLink: glivela.PrivateClientLink{Source: "10.20.0.3", Address: "10.20.0.2", SourceInterface: "ens8", Interface: "ens8"},
		ID:                "legacy-link",
		AccountID:         "account-example",
		Port:              24003,
	}}
	entry.Desired, err = NewEntryDesired(entryPlan, entryNet)
	if err != nil {
		t.Fatal(err)
	}
	beforeEntryRev := entry.Desired.Revision
	entry.Receipt, entry.ReportedAt = nil, time.Time{}
	rawNodes[entryCert] = entry

	target := rawNodes[landingCert]
	targetPlan := *target.Desired.clone().Landing
	targetPlan.Revision++
	targetPlan.ClientListeners = append(targetPlan.ClientListeners, glivela.TransportListener{
		ID:        legacyActive.ID,
		Port:      legacyActive.Port,
		Key:       legacyActive.Key,
		Source:    legacyActive.SourceIPv6,
		Transport: "ipv6-ss2022",
		Address:   legacyActive.ServerIPv6,
	})
	target.Desired, err = NewDesired(targetPlan)
	if err != nil {
		t.Fatal(err)
	}
	beforeLandingRev := target.Desired.Revision
	target.Receipt, target.Checks, target.ReportedAt = nil, nil, time.Time{}
	rawNodes[landingCert] = target
	if err = s.commit(rawNodes); err != nil {
		t.Fatal(err)
	}

	namesPath := filepath.Join(filepath.Dir(s.path), subscriptionNamesFile)
	if err = os.WriteFile(namesPath, []byte(`{"version":1,"names":{"legacy-tombstone":"Historical Retired Chain"}}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Reload must succeed with historical tombstones + subscription-names.json and prune
	// stale client-only SpeedPeers, ClientLinks, and landing ClientListeners on startup.
	reloaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = reloaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal("reload failed with historical client-chain tombstones:", err)
	}
	if reloaded.nodes[entryCert].Desired.Revision != beforeEntryRev+1 || len(reloaded.nodes[entryCert].Desired.EntryNetwork.SpeedPeers) != 0 || len(reloaded.nodes[entryCert].Desired.Entry.ClientLinks) != 0 {
		t.Fatal("startup reload did not prune retired client-chain SpeedPeers or ClientLinks")
	}
	if reloaded.nodes[landingCert].Desired.Revision != beforeLandingRev+1 || len(reloaded.nodes[landingCert].Desired.Landing.ClientListeners) != 0 {
		t.Fatal("startup reload did not prune retired client-chain landing listener")
	}
	if _, changed, err := projectBusinessEntries(reloaded.nodes, reloaded.business.material, time.Now()); err != nil || changed {
		t.Fatalf("subsequent projection after reload was not idempotent: changed=%v err=%v", changed, err)
	}
	if !reflect.DeepEqual(next.TrafficCounters, reloaded.business.material.TrafficCounters) || !reflect.DeepEqual(next.SubscriptionTokens, reloaded.business.material.SubscriptionTokens) {
		t.Fatal("historical reload altered accounting or subscription tokens")
	}

	// Subscriptions must never emit dialer-proxy or chain entries even when legacy records exist.
	mihomo := getSubscription(t, reloaded, "/sub/example-token?format=mihomo", "Mihomo")
	if mihomo.Code != 200 || strings.Contains(mihomo.Body.String(), "dialer-proxy:") || strings.Contains(mihomo.Body.String(), legacyActive.Name) {
		t.Fatalf("Mihomo subscription leaked retired client chain: code=%d body=%s", mihomo.Code, mihomo.Body.String())
	}
	shadow := getSubscription(t, reloaded, "/sub/example-token?format=shadowrocket", "Shadowrocket")
	if shadow.Code != 200 || strings.Contains(shadow.Body.String(), "chain=") || strings.Contains(shadow.Body.String(), "ss://") {
		t.Fatalf("Shadowrocket subscription leaked retired client chain: code=%d body=%s", shadow.Code, shadow.Body.String())
	}

	// Path MTU must reject retired mode="client".
	if _, _, err = reloaded.pathMTUTargetLocked("client", legacyActive.ID, legacyActive.EgressID); err == nil {
		t.Fatal("path MTU accepted retired client mode")
	}

	// Legacy enabled ClientChain records must not deadlock returned landing/entry retirement.
	disabledMaterial := reloaded.business.material
	accounts := append([]glivela.ImportAccount(nil), disabledMaterial.Plan.Accounts...)
	for i := range accounts {
		grants := append([]glivela.RouteGrant(nil), accounts[i].Grants...)
		for j := range grants {
			grants[j].Enabled = false
		}
		accounts[i].Grants = grants
	}
	disabledMaterial.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		t.Fatal(err)
	}
	retiredMat, removed, err := retiredNodeMaterial(disabledMaterial, RetireLandingChange{ID: "landing-example", CertificateID: landingCert, ExpectedRevision: reloaded.nodes[landingCert].Desired.Revision}, false)
	if err != nil {
		t.Fatal("legacy enabled ClientChain blocked landing retirement:", err)
	}
	if len(retiredMat.ClientChains) != 0 || !removed[tombstone.ID] || !removed[legacyActive.ID] {
		t.Fatalf("retired landing did not purge historical client chains: chains=%d removed=%v", len(retiredMat.ClientChains), removed)
	}
}
