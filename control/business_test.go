package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	glivela "github.com/petauron/glivela"
)

func stagedBusinessStore(t *testing.T) (*Store, string, glivela.ImportMaterial) {
	t.Helper()
	s := store(t)
	dir := filepath.Dir(s.path)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := dataImportFixture(t)
	transfer, storage := bytes.Repeat([]byte{21}, 32), bytes.Repeat([]byte{22}, 32)
	sealed, err := glivela.SealImportMaterial(m, transfer, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if err := StageImport(dir, "snapshot-example", sealed, transfer, storage); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "business.key")
	if err := os.WriteFile(keyPath, storage, 0600); err != nil {
		t.Fatal(err)
	}
	return s, keyPath, m
}

func TestControllerLoadsOriginalBusinessWithoutActivating(t *testing.T) {
	s, key, m := stagedBusinessStore(t)
	dir := filepath.Dir(s.path)
	checkpoint := filepath.Join(dir, "business.pending.json")
	before, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := LockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LoadBusiness(key); err != nil {
		t.Fatal(err)
	}
	view := s.Business()
	if view.State != "awaiting-handover" || view.SnapshotID != "snapshot-example" || len(view.Accounts) != 1 || len(view.Endpoints) != 1 || len(view.Nodes) != 1 {
		t.Fatalf("incorrect imported inventory: %+v", view)
	}
	account := view.Accounts[0]
	if account.Account != m.Plan.Accounts[0].Account || account.Schedule != m.ResetSchedules[account.Account.ID] || !reflect.DeepEqual(account.Usage, m.Plan.Accounts[0].Usage) || !reflect.DeepEqual(account.Traffic, m.TrafficCounters) {
		t.Fatal("loaded inventory changed original account or ledger")
	}
	endpoint := view.Endpoints[0]
	if endpoint.ID != m.Endpoints[0].Reality.ID || endpoint.EntryID != m.Endpoints[0].Reality.EntryID || endpoint.ServiceID != m.Endpoints[0].ServiceID || endpoint.NodeID != m.References.Applications[endpoint.EntryID].NodeID {
		t.Fatal("endpoint binding changed")
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"example-token", m.ProtocolSecrets["credential-example"], "synthetic-private-key", "synthetic-event", "subscriptionTokens", "retainedSource", "privateKey"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private migration material in management response")
		}
	}
	view.Accounts[0].Account.DisplayName = "changed"
	view.Accounts[0].Usage[0].Observed++
	view.Accounts[0].Traffic["credential-example"] = glivela.ImportTrafficCounters{}
	view.Nodes[0].Name = "changed"
	view.Endpoints[0].Name = "changed"
	if reflect.DeepEqual(view, s.Business()) {
		t.Fatal("inventory view aliases controller business state")
	}
	if !reflect.DeepEqual(s.business.material, m) {
		t.Fatal("view mutation changed private state")
	}
	if s.LoadBusiness(key) == nil {
		t.Fatal("business state reloaded over live controller")
	}
	after, err := os.ReadFile(checkpoint)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("loading rewrote checkpoint", err)
	}
	unlock()
	reopened, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.LoadBusiness(key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.Business(), s.Business()) {
		t.Fatal("business identity changed across restart")
	}
}

func TestControllerBusinessLoadingFailsClosed(t *testing.T) {
	for _, fault := range []string{"missing-key", "wrong-key", "short-key", "public-key", "symlink-key", "relative-key", "corrupt-checkpoint", "missing-checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			s, key, _ := stagedBusinessStore(t)
			switch fault {
			case "missing-key":
				key = ""
			case "wrong-key":
				if err := os.WriteFile(key, bytes.Repeat([]byte{23}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			case "short-key":
				if err := os.WriteFile(key, []byte("short"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-key":
				if err := os.Chmod(key, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-key":
				link := key + ".link"
				if err := os.Symlink(key, link); err != nil {
					t.Fatal(err)
				}
				key = link
			case "relative-key":
				key = "business.key"
			case "corrupt-checkpoint":
				if err := os.WriteFile(filepath.Join(filepath.Dir(s.path), "business.pending.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-checkpoint":
				if err := os.Remove(filepath.Join(filepath.Dir(s.path), "business.pending.json")); err != nil {
					t.Fatal(err)
				}
			}
			if s.LoadBusiness(key) == nil || s.business != nil || s.Business().State != "empty" {
				t.Fatal("failed load exposed partial business state")
			}
		})
	}
	s := store(t)
	if err := s.LoadBusiness(""); err != nil || s.Business().State != "empty" {
		t.Fatal("new controller without import refused", err)
	}
}

func TestBusinessAPIPreserves64BitValuesForBrowserClients(t *testing.T) {
	const large int64 = 9007199254740993
	a := BusinessAccount{Account: glivela.Account{ID: "account-example", Plan: glivela.AccountPlan{TotalBytes: large, ExpiryTime: large}, DesiredRevision: uint64(large), AppliedRevision: uint64(large)},
		Usage:   []glivela.UsageMember{{CredentialID: "credential-example", Baseline: large, Observed: large}},
		Traffic: map[string]glivela.ImportTrafficCounters{"credential-example": {UploadBytes: large, DownloadBytes: large, RawUploadBytes: large, RawDownloadBytes: large}}}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Account struct {
			Plan            map[string]any
			DesiredRevision string
			AppliedRevision string
		}
		Usage []struct {
			Baseline string
			Observed string
		}
		Traffic map[string]struct {
			UploadBytes      string
			DownloadBytes    string
			RawUploadBytes   string
			RawDownloadBytes string
		}
	}
	if json.Unmarshal(raw, &view) != nil {
		t.Fatal("counter API did not use exact decimal strings")
	}
	const want = "9007199254740993"
	traffic := view.Traffic["credential-example"]
	if view.Account.Plan["totalBytes"] != want || view.Account.Plan["expiryTime"] != want || view.Account.DesiredRevision != want || view.Account.AppliedRevision != want || len(view.Usage) != 1 || view.Usage[0].Baseline != want || view.Usage[0].Observed != want || traffic.UploadBytes != want || traffic.DownloadBytes != want || traffic.RawUploadBytes != want || traffic.RawDownloadBytes != want {
		t.Fatal("64-bit API value rounded or omitted")
	}
}
