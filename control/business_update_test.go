package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func businessBytes(t *testing.T, s *Store) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(s.path), "business.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOwnedAccountPlanUpdatePreservesDataAndReconcilesOnlyAffectedEntry(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, true)
	reportRuntime(t, s, cert, d)
	before := s.business.material
	beforeBytes := businessBytes(t, s)
	plan := before.Plan.Accounts[0].Account.Plan
	plan.Enabled = false
	status, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, plan)
	if err != nil || status.DesiredRevision != 8 || status.AppliedRevision != 6 || status.State != "reconciling" || !reflect.DeepEqual(status.PendingEntries, []string{"entry-example"}) {
		t.Fatal("saved update was not reported as pending runtime application", status, err)
	}
	node := s.nodes[cert]
	if node.Desired.Revision != d.Revision+1 || node.Receipt != nil {
		t.Fatal("old runtime receipt survived credential projection")
	}
	for _, material := range node.Desired.Entry.Credentials {
		if material.Credential.AccountID == "account-example" && (material.Credential.Enabled || bytes.Contains(node.Desired.Config, []byte(material.ProtocolID))) {
			t.Fatal("disabled credential remained in generated client authentication")
		}
		if material.Credential.AccountID == "account-other" && !material.Credential.Enabled {
			t.Fatal("one account disabled a different account sharing the entry")
		}
	}
	if len(node.Desired.Entry.Grants) != 1 || node.Desired.Entry.Grants[0].Deployable() || len(node.Desired.EntryNetwork.Peers) != 1 {
		t.Fatal("disabled grant lost its configuration or remained deployable")
	}
	if w := getSubscription(t, s, "/sub/example-token", ""); w.Code != 404 {
		t.Fatal("disabled account still downloaded credentials")
	}
	after := s.business.material
	unchanged := after
	accounts := append([]glivela.ImportAccount{}, after.Plan.Accounts...)
	accounts[0].Account = before.Plan.Accounts[0].Account
	unchanged.Plan, err = glivela.PlanImport(accounts)
	if err != nil || !reflect.DeepEqual(unchanged, before) {
		t.Fatal("plan edit changed credentials, ownership, ledger, reset cycles or history", err)
	}
	if bytes.Equal(beforeBytes, businessBytes(t, s)) {
		t.Fatal("edited owned plan was not persisted")
	}
	written := businessBytes(t, s)
	if _, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err != nil || !bytes.Equal(written, businessBytes(t, s)) || s.nodes[cert].Desired.Revision != node.Desired.Revision {
		t.Fatal("lost-response retry resealed data or advanced runtime twice", err)
	}
	// A real node would independently inspect Xray. This synthetic receipt
	// proves the reconciliation/status contract only, not actual auth denial.
	reportRuntime(t, s, cert, node.Desired)
	status, err = s.UpdateAccountPlan(context.Background(), "account-example", 8, plan)
	if err != nil || status.State != "entry-runtime-verified" || status.AppliedRevision != 6 {
		t.Fatal("runtime status masqueraded as final business/route acceptance", status, err)
	}
	plan.Enabled = true
	if _, err := s.UpdateAccountPlan(context.Background(), "account-example", 8, plan); err != nil {
		t.Fatal(err)
	}
	reenabled := s.nodes[cert].Desired
	if reenabled.Revision != d.Revision+2 || reenabled.Entry.Credentials[0].ProtocolID != d.Entry.Credentials[0].ProtocolID || !reenabled.Entry.Grants[0].Deployable() {
		t.Fatal("reenabling regenerated or lost original route/credential identity")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.business.material, s.business.material) || loaded.nodes[cert].Desired.Revision != reenabled.Revision {
		t.Fatal("restart replayed old import or repeatedly projected same account update")
	}
}

func TestAccountSaveSurvivesNodeProjectionWriteFailureWithoutSnapshotReplay(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	reportRuntime(t, s, cert, d)
	plan := s.business.material.Plan.Accounts[0].Account.Plan
	plan.TotalBytes = 400
	// Refuse nodes.json replacement after the encrypted authoritative save.
	saved := s.path + ".fixture-saved"
	if err := os.Rename(s.path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err == nil {
		t.Fatal("projection storage failure reported successful update")
	}
	if s.business.material.Plan.Accounts[0].Account.DesiredRevision != 8 || s.nodes[cert].Desired.Revision != d.Revision {
		t.Fatal("saved source was rolled back or unpersisted projection became authoritative")
	}
	committed := businessBytes(t, s)
	if w := getSubscription(t, s, "/sub/example-token", ""); w.Code != 404 {
		t.Fatal("newly exhausted quota ignored while projection pending")
	}
	if _, err := s.Exchange(context.Background(), cert, nil); err == nil {
		t.Fatal("unpersisted new desired policy delivered")
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
	if loaded.nodes[cert].Desired.Revision != d.Revision+1 || loaded.nodes[cert].Desired.Entry.Credentials[0].Credential.Enabled {
		t.Fatal("restart failed to derive latest saved quota gate")
	}
	if _, err := loaded.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err != nil || !bytes.Equal(committed, businessBytes(t, loaded)) {
		t.Fatal("retry overwrote ledger or replayed a stale checkpoint", err)
	}
}

func TestAccountPlanUpdateRejectsStaleConcurrentAndUnownedWrites(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	plan := s.business.material.Plan.Accounts[0].Account.Plan
	before := businessBytes(t, s)
	conflicting := plan
	conflicting.TotalBytes++
	for _, expected := range []uint64{0, 6, 9} {
		if _, err := s.UpdateAccountPlan(context.Background(), "account-example", expected, conflicting); err == nil {
			t.Fatal("stale/future revision accepted", expected)
		}
	}
	bad := plan
	bad.TotalBytes = -1
	if _, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, bad); err == nil {
		t.Fatal("invalid quota accepted")
	}
	if !bytes.Equal(before, businessBytes(t, s)) {
		t.Fatal("refused update changed owned file")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, limit := range []int64{12000, 13000} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := plan
			next.TotalBytes = limit
			_, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, next)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent stale plans both committed", success)
	}
	staged, key, _ := stagedBusinessStore(t)
	if err := staged.LoadBusiness(key); err != nil {
		t.Fatal(err)
	}
	if _, err := staged.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err == nil {
		t.Fatal("staging granted live mutation authority")
	}
}

func TestChangedOwnedStorageFencesBusinessAndDoesNotOverwrite(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	reportRuntime(t, s, cert, d)
	path := filepath.Join(filepath.Dir(s.path), "business.json")
	if err := os.WriteFile(path, []byte("corrupt anonymous fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := s.business.material.Plan.Accounts[0].Account.Plan
	plan.Enabled = false
	if _, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err == nil {
		t.Fatal("changed authoritative file was overwritten")
	}
	if s.Business().State != "storage-unverified" {
		t.Fatal("storage uncertainty was hidden")
	}
	if w := getSubscription(t, s, "/sub/example-token", ""); w.Code != 503 {
		t.Fatal("uncertain storage still published accounts")
	}
	if _, err := s.Exchange(context.Background(), cert, nil); err == nil {
		t.Fatal("uncertain storage still issued desired configuration")
	}
	if string(businessBytes(t, s)) != "corrupt anonymous fixture" {
		t.Fatal("unknown owned state silently repaired from old memory/staging")
	}
}

func TestAccountPlanHTTPRequiresAdministratorAndExactCompleteValues(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	_, ca, key := identity(t, nil, nil, false)
	serverID, _, _ := identity(t, ca, key, true)
	adminID, adminCert, _ := identity(t, ca, key, false)
	nodeID, _, _ := identity(t, ca, key, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server, err := NewServer("127.0.0.1:0", s, serverID, roots, []string{CertificateID(adminCert)})
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
	admin, node := client(adminID), client(nodeID)
	post := func(client *http.Client, body string, want int) []byte {
		t.Helper()
		response, err := client.Post(listener.URL+"/v1/admin/account-plan", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unexpected account update response", response.StatusCode, want, err)
		}
		return raw
	}
	body := `{"accountId":"account-example","expectedRevision":"7","plan":{"totalBytes":"9007199254740993","expiryTime":"0","resetDays":30,"enabled":true}}`
	post(node, body, 403)
	for _, bad := range []string{`{"accountId":"account-example","expectedRevision":"7","plan":{}}`, strings.Replace(body, `"9007199254740993"`, `9007199254740993`, 1), strings.Replace(body, `"enabled":true`, `"enabled":true,"protocolSecret":"forbidden"`, 1), strings.Replace(body, `"resetDays":30,`, ``, 1)} {
		post(admin, bad, 400)
	}
	raw := post(admin, body, 202)
	var status AccountChangeResult
	if json.Unmarshal(raw, &status) != nil || status.DesiredRevision != 8 || s.business.material.Plan.Accounts[0].Account.Plan.TotalBytes != 9007199254740993 {
		t.Fatal("64-bit plan changed or save confused with apply")
	}
	for _, secret := range []string{"example-token", "protocolId", "privateKey", "businessKey"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("account update response disclosed private data")
		}
	}
}

func TestAccountExpiryProjectsOnAuthenticatedPollWithoutRepeatedRestart(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	reportRuntime(t, s, cert, d)
	plan := s.business.material.Plan.Accounts[0].Account.Plan
	plan.ExpiryTime = time.Now().Add(200 * time.Millisecond).UnixMilli()
	if _, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, plan); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[cert].Desired.Revision
	if wait := time.Until(time.UnixMilli(plan.ExpiryTime)); wait > 0 {
		time.Sleep(wait + time.Millisecond)
	}
	if _, err := s.Exchange(context.Background(), strings.Repeat("e", 64), nil); err == nil || s.nodes[cert].Desired.Revision != before {
		t.Fatal("unknown certificate triggered a state mutation")
	}
	desired, err := s.Exchange(context.Background(), cert, nil)
	if err != nil || desired.Revision != before+1 || desired.Entry.Credentials[0].Credential.Enabled {
		t.Fatal("expiry did not close this account's authentication gate", err)
	}
	for range 3 {
		next, err := s.Exchange(context.Background(), cert, nil)
		if err != nil || next.Revision != desired.Revision {
			t.Fatal("expired unchanged account caused repeated activation", err)
		}
	}
}

func TestMissingOwnedCredentialCannotClaimAccountRuntimeVerified(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, false)
	plan := *d.clone().Entry
	plan.Credentials = plan.Credentials[1:]
	plan.Revision++
	desired, err := NewEntryDesired(plan, EntryNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: desired}); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, cert, desired)
	accountPlan := s.business.material.Plan.Accounts[0].Account.Plan
	accountPlan.TotalBytes++
	result, err := s.UpdateAccountPlan(context.Background(), "account-example", 7, accountPlan)
	if err != nil || result.State != "reconciling" || len(result.PendingEntries) != 1 {
		t.Fatal("incomplete account inventory was reported verified", result, err)
	}
}
