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

func dataImportFixture(t *testing.T) glivela.ImportMaterial {
	t.Helper()
	secret := "11111111-1111-4111-8111-111111111111"
	account := glivela.Account{ID: "account-example", DisplayName: "Example", Plan: glivela.AccountPlan{Enabled: true}, DesiredRevision: 7, AppliedRevision: 6}
	credential := glivela.Credential{ID: "credential-example", AccountID: account.ID, Kind: glivela.NativeCredential, User: "example", Identity: glivela.Identity(secret), EntryID: "entry-example", Enabled: true}
	plan, err := glivela.PlanImport([]glivela.ImportAccount{{Account: account, SubscriptionTokenFingerprint: glivela.SubscriptionTokenFingerprint("example-token"), Credentials: []glivela.Credential{credential}, Usage: []glivela.UsageMember{{CredentialID: credential.ID, Baseline: 1000, Observed: 5000, Active: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	m := glivela.ImportMaterial{Plan: plan, SubscriptionTokens: map[string]string{account.ID: "example-token"}, ProtocolSecrets: map[string]string{credential.ID: secret},
		ResetSchedules:  map[string]glivela.ImportResetSchedule{account.ID: {NextResetAt: "2026-11-03T00:00:00Z"}},
		TrafficCounters: map[string]glivela.ImportTrafficCounters{credential.ID: {UploadBytes: 2000, DownloadBytes: 3000, RawUploadBytes: 4000, RawDownloadBytes: 6000}},
	}
	m.Endpoints = []glivela.ImportEndpoint{{Reality: glivela.RealityEndpoint{ID: "endpoint-example", EntryID: "entry-example", InboundTag: "inbound-example", ListenAddress: "100.64.0.2", ListenPort: 10443, AdvertiseHost: "entry.example.test", AdvertisePort: 443, Target: "www.example.com:443", ServerNames: []string{"www.example.com"}, PrivateKey: "synthetic-private-key", PublicKey: "synthetic-public-key", ShortIDs: []string{"abcd"}, Fingerprint: "chrome"}, ServiceID: "service-example", TargetIP: "203.0.113.20", VLESSEnabled: true, DesiredRevision: 3, AppliedRevision: 2, PreviousStatus: "failed", CreatedAt: "2026-10-19T00:00:00Z", UpdatedAt: "2026-10-19T02:03:04Z", SourcePeerJSON: json.RawMessage(`{}`)}}
	m.SourceSHA256 = glivela.Identity("synthetic-source")
	m.RetainedSource, err = json.Marshal(map[string]any{"version": 1, "sourceSchema": 113, "snapshotId": "snapshot-example", "sourceSha256": m.SourceSHA256, "history": []string{"synthetic-event"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestImportPersistsWithoutReinitializing(t *testing.T) {
	r, _ := nativeFixture(t)
	material := dataImportFixture(t)
	transferKey, storageKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	sealed, err := glivela.SealImportMaterial(material, transferKey, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	if StageImport(r.Directory, "snapshot-example", sealed, transferKey, bytes.Clone(transferKey)) == nil {
		t.Fatal("equal key material accepted")
	}
	if err := StageImport(r.Directory, "snapshot-example", sealed, transferKey, storageKey); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.Directory, "business.pending.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("example-token")) || bytes.Contains(before, []byte(material.ProtocolSecrets["credential-example"])) {
		t.Fatal("plaintext credentials persisted")
	}
	got, id, err := ReadStagedImport(r.Directory, storageKey)
	if err != nil || id != "snapshot-example" || !reflect.DeepEqual(got, material) {
		t.Fatal("account identities or counters changed", err)
	}
	if _, _, err := ReadStagedImport(r.Directory, transferKey); err == nil {
		t.Fatal("temporary transfer key still decrypts stored state")
	}
	if err := StageImport(r.Directory, "snapshot-example", sealed, transferKey, storageKey); err != nil {
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
	if StageImport(r.Directory, "snapshot-example", changed, transferKey, storageKey) == nil {
		t.Fatal("changed snapshot overwrote ledger")
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed import changed checkpoint")
	}
}

func TestImportRefusesRunningControllerAndUnsafeState(t *testing.T) {
	r, _ := nativeFixture(t)
	key := bytes.Repeat([]byte{3}, 32)
	storageKey := bytes.Repeat([]byte{4}, 32)
	sealed, err := glivela.SealImportMaterial(dataImportFixture(t), key, "snapshot-example")
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := LockDirectory(r.Directory)
	if err != nil {
		t.Fatal(err)
	}
	err = StageImport(r.Directory, "snapshot-example", sealed, key, storageKey)
	unlock()
	if err == nil {
		t.Fatal("import ran alongside controller")
	}
	path := filepath.Join(r.Directory, "business.pending.json")
	if err := os.Symlink("absent", path); err != nil {
		t.Fatal(err)
	}
	if StageImport(r.Directory, "snapshot-example", sealed, key, storageKey) == nil {
		t.Fatal("symlink checkpoint accepted")
	}
}

func TestImportRetryRejectsChangedStateOutsidePlanHash(t *testing.T) {
	for _, field := range []string{"schedule", "counters", "endpoint", "history", "source"} {
		t.Run(field, func(t *testing.T) {
			r, _ := nativeFixture(t)
			m := dataImportFixture(t)
			transfer, storage := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
			stage := func() error {
				sealed, err := glivela.SealImportMaterial(m, transfer, "snapshot-example")
				if err != nil {
					return err
				}
				return StageImport(r.Directory, "snapshot-example", sealed, transfer, storage)
			}
			if err := stage(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.Directory, "business.pending.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			hash := m.Plan.SHA256
			if field == "schedule" {
				s := m.ResetSchedules["account-example"]
				s.NextResetAt = "2026-12-03T00:00:00Z"
				m.ResetSchedules["account-example"] = s
			} else if field == "counters" {
				c := m.TrafficCounters["credential-example"]
				c.RawUploadBytes++
				m.TrafficCounters["credential-example"] = c
			} else if field == "endpoint" {
				m.Endpoints[0].Reality.PublicKey = "changed-synthetic-public-key"
			} else if field == "history" {
				m.RetainedSource = bytes.Replace(m.RetainedSource, []byte("synthetic-event"), []byte("changed-event"), 1)
			} else {
				previous := m.SourceSHA256
				m.SourceSHA256 = glivela.Identity("changed-source")
				m.RetainedSource = bytes.ReplaceAll(m.RetainedSource, []byte(previous), []byte(m.SourceSHA256))
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

func TestImportCorruptionNeverReturnsPartialBusinessState(t *testing.T) {
	for _, kind := range []string{"truncated", "ciphertext", "snapshot", "version"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := nativeFixture(t)
			transfer, storage := bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 32)
			sealed, err := glivela.SealImportMaterial(dataImportFixture(t), transfer, "snapshot-example")
			if err != nil {
				t.Fatal(err)
			}
			if err := StageImport(r.Directory, "snapshot-example", sealed, transfer, storage); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.Directory, "business.pending.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record stagedImport
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			if kind == "truncated" {
				raw = raw[:len(raw)/2]
			} else {
				switch kind {
				case "ciphertext":
					record.Sealed[len(record.Sealed)-1] ^= 1
				case "snapshot":
					record.SnapshotID = "different-snapshot"
				case "version":
					record.Version = 2
				}
				raw, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, id, err := ReadStagedImport(r.Directory, storage)
			if err == nil || id != "" || len(got.Plan.Accounts) != 0 || len(got.Endpoints) != 0 || len(got.RetainedSource) != 0 {
				t.Fatal("partial/unverified import exposed")
			}
			if err := StageImport(r.Directory, "snapshot-example", sealed, transfer, storage); err == nil {
				t.Fatal("corrupt checkpoint silently replaced")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("failed retry erased recovery evidence", err)
			}
		})
	}
}
