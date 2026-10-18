package glivela

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func importFixture(t *testing.T) ImportMaterial {
	t.Helper()
	account := Account{ID: "account-a", DisplayName: "Fixture", Plan: AccountPlan{Enabled: true}, DesiredRevision: 7, AppliedRevision: 6}
	secret := "11111111-1111-4111-8111-111111111111"
	credential := Credential{ID: "native-a", AccountID: account.ID, Kind: NativeCredential, User: "Fixture", Identity: Identity(secret), EntryID: "entry-a", Enabled: true}
	plan, err := PlanImport([]ImportAccount{{Account: account, SubscriptionTokenFingerprint: SubscriptionTokenFingerprint("fixture-token"), Credentials: []Credential{credential}, HysteriaIdentities: map[string]string{credential.ID: Identity("fixture-hy2")}, Usage: []UsageMember{{CredentialID: credential.ID, Baseline: 987654321, Observed: 1987654321, Active: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	m := ImportMaterial{Plan: plan, SubscriptionTokens: map[string]string{account.ID: "fixture-token"}, ProtocolSecrets: map[string]string{credential.ID: secret}, HysteriaSecrets: map[string]string{credential.ID: "fixture-hy2"},
		ResetSchedules:  map[string]ImportResetSchedule{account.ID: {LastResetAt: "2026-10-03T00:00:00+08:00", NextResetAt: "2026-11-03T00:00:00+08:00"}},
		TrafficCounters: map[string]ImportTrafficCounters{credential.ID: {UploadBytes: 123456789, DownloadBytes: 876543210, RawUploadBytes: 1123456789, RawDownloadBytes: 1876543210, StartedAt: "2026-10-03T00:00:00+08:00", ObservedAt: "2026-10-18T02:03:04.123456789Z", WatermarkObservedAt: "2026-10-18T02:03:04Z"}},
	}
	m.Endpoints = []ImportEndpoint{importEndpointFixture(t)}
	bindImportFixture(t, &m, "snapshot-a")
	return m
}

func bindImportFixture(t *testing.T, m *ImportMaterial, snapshot string) {
	t.Helper()
	m.SourceSHA256 = Identity("synthetic-source-" + snapshot)
	raw, err := json.Marshal(map[string]any{"version": 1, "sourceSchema": 113, "snapshotId": snapshot, "sourceSha256": m.SourceSHA256, "history": []string{"synthetic-event"}})
	if err != nil {
		t.Fatal(err)
	}
	m.RetainedSource = raw
}

func TestImportMaterialPreservesOriginalIdentitiesAndCounters(t *testing.T) {
	m := importFixture(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	sealed, err := SealImportMaterial(m, key, "snapshot-a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("fixture-token")) {
		t.Fatal("plaintext transfer")
	}
	opened, err := OpenImportMaterial(sealed, key, "snapshot-a")
	if err != nil || !reflect.DeepEqual(m, opened) {
		t.Fatal("transfer changed identity, revision or counters")
	}
	second, err := SealImportMaterial(m, key, "snapshot-a")
	if err != nil || bytes.Equal(second, sealed) {
		t.Fatal("nonce reused")
	}
	if _, err := OpenImportMaterial(sealed, key, "snapshot-b"); err == nil {
		t.Fatal("snapshot substitution accepted")
	}
	if _, err := OpenImportMaterial(sealed, bytes.Repeat([]byte{0x43}, 32), "snapshot-a"); err == nil {
		t.Fatal("wrong key accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenImportMaterial(sealed, key, "snapshot-a"); err == nil {
		t.Fatal("corrupted material accepted")
	}
}

func TestImportMaterialRejectsMissingChangedAndOrphanedSecrets(t *testing.T) {
	for _, change := range []func(*ImportMaterial){
		func(m *ImportMaterial) { delete(m.SubscriptionTokens, "account-a") },
		func(m *ImportMaterial) { m.SubscriptionTokens["account-a"] = "replacement" },
		func(m *ImportMaterial) { m.ProtocolSecrets["native-a"] = "22222222-2222-4222-8222-222222222222" },
		func(m *ImportMaterial) { delete(m.HysteriaSecrets, "native-a") },
		func(m *ImportMaterial) { m.ProtocolSecrets["orphan"] = "unused" },
		func(m *ImportMaterial) { m.Plan.Accounts[0].Usage[0].Observed++ },
	} {
		m := importFixture(t)
		change(&m)
		if m.Validate() == nil {
			t.Fatal("incomplete or substituted material accepted")
		}
	}
}

func TestImportBindsCompleteSourceAndEndpointInventory(t *testing.T) {
	for name, change := range map[string]func(*ImportMaterial){
		"missing source":            func(m *ImportMaterial) { m.RetainedSource = nil },
		"different source hash":     func(m *ImportMaterial) { m.SourceSHA256 = Identity("different-source") },
		"missing endpoint":          func(m *ImportMaterial) { m.Endpoints = nil },
		"different source identity": func(m *ImportMaterial) { bindImportFixture(t, m, "snapshot-other") },
	} {
		t.Run(name, func(t *testing.T) {
			m := importFixture(t)
			change(&m)
			if _, err := SealImportMaterial(m, bytes.Repeat([]byte{7}, 32), "snapshot-a"); err == nil {
				t.Fatal("partial or substituted handover accepted")
			}
		})
	}
}

func TestImportPreservesUnassignedAccountWithoutInventingAccess(t *testing.T) {
	account := Account{ID: "account-unassigned", DisplayName: "Unassigned", Plan: AccountPlan{Enabled: true, TotalBytes: 123456789}, DesiredRevision: 2, AppliedRevision: 1}
	plan, err := PlanImport([]ImportAccount{{Account: account, SubscriptionTokenFingerprint: SubscriptionTokenFingerprint("unassigned-token")}})
	if err != nil {
		t.Fatal(err)
	}
	m := ImportMaterial{Plan: plan, SubscriptionTokens: map[string]string{account.ID: "unassigned-token"}, ResetSchedules: map[string]ImportResetSchedule{account.ID: {NextResetAt: "2026-11-19T00:00:00Z"}}}
	bindImportFixture(t, &m, "snapshot-unassigned")
	key := bytes.Repeat([]byte{6}, 32)
	sealed, err := SealImportMaterial(m, key, "snapshot-unassigned")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenImportMaterial(sealed, key, "snapshot-unassigned")
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan.Accounts[0].Account != account || len(got.Plan.Accounts[0].Credentials) != 0 || len(got.TrafficCounters) != 0 {
		t.Fatal("unassigned account was reinitialized")
	}
	if _, err := ProjectQuota(account.Plan, got.Plan.Accounts[0].Usage); err == nil {
		t.Fatal("unassigned account granted live quota")
	}
	for _, change := range []func(*ImportAccount){
		func(a *ImportAccount) { a.Usage = []UsageMember{{CredentialID: "phantom", Observed: 1}} },
		func(a *ImportAccount) { a.HysteriaIdentities = map[string]string{"phantom": Identity("secret")} },
		func(a *ImportAccount) { a.Grants = []RouteGrant{{ID: "phantom"}} },
	} {
		a := ImportAccount{Account: account, SubscriptionTokenFingerprint: SubscriptionTokenFingerprint("unassigned-token")}
		change(&a)
		if _, err := PlanImport([]ImportAccount{a}); err == nil {
			t.Fatal("unassigned account accepted orphaned access or usage")
		}
	}
}
