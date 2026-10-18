package control

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	glivela "github.com/petauron/glivela"
)

func accountImportFixture(t *testing.T) glivela.ImportMaterial {
	t.Helper()
	secret := "11111111-1111-4111-8111-111111111111"
	account := glivela.Account{ID: "account-example", DisplayName: "Example", Plan: glivela.AccountPlan{Enabled: true}, DesiredRevision: 7, AppliedRevision: 6}
	credential := glivela.Credential{ID: "credential-example", AccountID: account.ID, Kind: glivela.NativeCredential, User: "example", Identity: glivela.Identity(secret), EntryID: "entry-example", Enabled: true}
	plan, err := glivela.PlanImport([]glivela.ImportAccount{{Account: account, SubscriptionTokenFingerprint: glivela.SubscriptionTokenFingerprint("example-token"), Credentials: []glivela.Credential{credential}, Usage: []glivela.UsageMember{{CredentialID: credential.ID, Baseline: 1000, Observed: 5000, Active: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	return glivela.ImportMaterial{Plan: plan, SubscriptionTokens: map[string]string{account.ID: "example-token"}, ProtocolSecrets: map[string]string{credential.ID: secret},
		ResetSchedules:  map[string]glivela.ImportResetSchedule{account.ID: {NextResetAt: "2026-11-03T00:00:00Z"}},
		TrafficCounters: map[string]glivela.ImportTrafficCounters{credential.ID: {UploadBytes: 2000, DownloadBytes: 3000, RawUploadBytes: 4000, RawDownloadBytes: 6000}},
	}
}

func TestAccountImportPersistsWithoutReinitializing(t *testing.T) {
	r, _ := nativeFixture(t)
	material := accountImportFixture(t)
	transferKey, storageKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	sealed, err := glivela.SealImportMaterial(material, transferKey, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if StageAccountImport(r.Directory, "snapshot-example", sealed, transferKey, bytes.Clone(transferKey)) == nil {
		t.Fatal("equal key material accepted")
	}
	if err := StageAccountImport(r.Directory, "snapshot-example", sealed, transferKey, storageKey); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.Directory, "accounts.pending.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("example-token")) || bytes.Contains(before, []byte(material.ProtocolSecrets["credential-example"])) {
		t.Fatal("plaintext credentials persisted")
	}
	got, id, err := ReadStagedAccounts(r.Directory, storageKey)
	if err != nil || id != "snapshot-example" || !reflect.DeepEqual(got, material) {
		t.Fatal("account identities or counters changed", err)
	}
	if _, _, err := ReadStagedAccounts(r.Directory, transferKey); err == nil {
		t.Fatal("temporary transfer key still decrypts stored state")
	}
	if err := StageAccountImport(r.Directory, "snapshot-example", sealed, transferKey, storageKey); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retry rewrote committed checkpoint", err)
	}
	material.Plan.Accounts[0].Usage[0].Observed++
	material.Plan, err = glivela.PlanImport(material.Plan.Accounts)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := glivela.SealImportMaterial(material, transferKey, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if StageAccountImport(r.Directory, "snapshot-example", changed, transferKey, storageKey) == nil {
		t.Fatal("changed snapshot overwrote ledger")
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed import changed checkpoint")
	}
}

func TestAccountImportRefusesRunningControllerAndUnsafeState(t *testing.T) {
	r, _ := nativeFixture(t)
	key := bytes.Repeat([]byte{3}, 32)
	storageKey := bytes.Repeat([]byte{4}, 32)
	sealed, err := glivela.SealImportMaterial(accountImportFixture(t), key, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := LockDirectory(r.Directory)
	if err != nil {
		t.Fatal(err)
	}
	err = StageAccountImport(r.Directory, "snapshot-example", sealed, key, storageKey)
	unlock()
	if err == nil {
		t.Fatal("import ran alongside controller")
	}
	path := filepath.Join(r.Directory, "accounts.pending.json")
	if err := os.Symlink("absent", path); err != nil {
		t.Fatal(err)
	}
	if StageAccountImport(r.Directory, "snapshot-example", sealed, key, storageKey) == nil {
		t.Fatal("symlink checkpoint accepted")
	}
}

func TestAccountImportRetryRejectsChangedStateOutsidePlanHash(t *testing.T) {
	for _, field := range []string{"schedule", "counters"} {
		t.Run(field, func(t *testing.T) {
			r, _ := nativeFixture(t)
			m := accountImportFixture(t)
			transfer, storage := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
			stage := func() error {
				sealed, err := glivela.SealImportMaterial(m, transfer, "snapshot-example")
				if err != nil {
					return err
				}
				return StageAccountImport(r.Directory, "snapshot-example", sealed, transfer, storage)
			}
			if err := stage(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.Directory, "accounts.pending.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			hash := m.Plan.SHA256
			if field == "schedule" {
				s := m.ResetSchedules["account-example"]
				s.NextResetAt = "2026-12-03T00:00:00Z"
				m.ResetSchedules["account-example"] = s
			} else {
				c := m.TrafficCounters["credential-example"]
				c.RawUploadBytes++
				m.TrafficCounters["credential-example"] = c
			}
			if m.Plan.SHA256 != hash {
				t.Fatal("test changed plan digest")
			}
			if stage() == nil {
				t.Fatal("changed full snapshot accepted as retry")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected retry changed checkpoint", err)
			}
		})
	}
}
