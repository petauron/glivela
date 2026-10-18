package glivela

import (
	"bytes"
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
	return ImportMaterial{Plan: plan, SubscriptionTokens: map[string]string{account.ID: "fixture-token"}, ProtocolSecrets: map[string]string{credential.ID: secret}, HysteriaSecrets: map[string]string{credential.ID: "fixture-hy2"},
		ResetSchedules:  map[string]ImportResetSchedule{account.ID: {LastResetAt: "2026-10-03T00:00:00+08:00", NextResetAt: "2026-11-03T00:00:00+08:00"}},
		TrafficCounters: map[string]ImportTrafficCounters{credential.ID: {UploadBytes: 123456789, DownloadBytes: 876543210, RawUploadBytes: 1123456789, RawDownloadBytes: 1876543210, StartedAt: "2026-10-03T00:00:00+08:00", ObservedAt: "2026-10-18T02:03:04.123456789Z", WatermarkObservedAt: "2026-10-18T02:03:04Z"}},
	}
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
