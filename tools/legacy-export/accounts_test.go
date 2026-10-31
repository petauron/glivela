package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

func tableFixture(rows ...map[string]any) table {
	if len(rows) == 0 {
		return table{Columns: []string{"id"}, Rows: [][]cell{}}
	}
	columns := make([]string, 0, len(rows[0]))
	for name := range rows[0] {
		columns = append(columns, name)
	}
	slices.Sort(columns)
	t := table{Columns: columns, Rows: [][]cell{}}
	for _, values := range rows {
		row := make([]cell, len(columns))
		for i, column := range columns {
			switch v := values[column].(type) {
			case nil:
				row[i] = cell{Kind: "null"}
			case string:
				row[i] = cell{Kind: "text", Text: v}
			case int:
				row[i] = cell{Kind: "integer", Text: strconv.Itoa(v)}
			case int64:
				row[i] = cell{Kind: "integer", Text: strconv.FormatInt(v, 10)}
			default:
				panic("unsupported synthetic fixture")
			}
		}
		t.Rows = append(t.Rows, row)
	}
	return t
}

func accountRowsFixture() archive {
	const native = "11111111-1111-4111-8111-111111111111"
	const routed = "22222222-2222-4222-8222-222222222222"
	a := archive{Version: 1, Schema: 113, SnapshotID: "snapshot-example", SourceSHA256: glivela.Identity("synthetic-backup"), Tables: map[string]table{}, Secrets: map[string]secretValue{
		"token-secret":  {Context: "meridian-account:account-example", Value: []byte("example-token")},
		"native-secret": {Context: "meridian-credential:native-example", Value: []byte(native)},
		"route-secret":  {Context: "meridian-credential:route-example", Value: []byte(routed)},
		"hy2-secret":    {Context: "meridian-credential-hy2:native-example", Value: []byte("example-hy2")},
	}}
	for _, name := range archiveTables {
		a.Tables[name] = tableFixture()
	}
	a.Tables["meridian_endpoints"] = tableFixture(map[string]any{"id": "endpoint-example", "application_id": "entry-example", "inbound_tag": "inbound-example"})
	a.Tables["meridian_accounts"] = tableFixture(map[string]any{
		"id": "account-example", "display_name": "Example", "total_bytes": int64(9007199254740993), "expiry_time": int64(0), "reset_days": 30, "enabled": 1,
		"desired_revision": 7, "applied_revision": 6, "subscription_token_sha256": glivela.SubscriptionTokenFingerprint("example-token"), "subscription_token_secret_id": "token-secret",
		"next_reset_at": "2026-11-19T00:00:00+08:00", "last_reset_at": "2026-10-19T00:00:00+08:00",
	})
	a.Tables["meridian_credentials"] = tableFixture(
		map[string]any{"id": "native-example", "account_id": "account-example", "endpoint_id": "endpoint-example", "kind": "native", "user_name": "native-user", "identity_sha256": glivela.Identity(native), "protocol_secret_id": "native-secret", "hy2_auth_secret_id": "hy2-secret", "hy2_identity_sha256": glivela.Identity("example-hy2"), "egress_node_id": nil, "enabled": 1},
		map[string]any{"id": "route-example", "account_id": "account-example", "endpoint_id": "endpoint-example", "kind": "route", "user_name": "route-user", "identity_sha256": glivela.Identity(routed), "protocol_secret_id": "route-secret", "hy2_auth_secret_id": nil, "hy2_identity_sha256": "", "egress_node_id": "landing-example", "enabled": 0},
	)
	a.Tables["meridian_usage_watermarks"] = tableFixture(
		map[string]any{"credential_id": "native-example", "baseline_bytes": int64(9007199254740000), "observed_bytes": int64(9007199254740993), "raw_up_bytes": 12345, "raw_down_bytes": 23456, "observed_at": "2026-10-19T02:03:04.123456789Z"},
		map[string]any{"credential_id": "route-example", "baseline_bytes": 1000, "observed_bytes": 5000, "raw_up_bytes": 3000, "raw_down_bytes": 2000, "observed_at": "2026-10-19T02:03:04Z"},
	)
	a.Tables["meridian_line_usage"] = tableFixture(map[string]any{"credential_id": "native-example", "upload_bytes": 123, "download_bytes": 456, "started_at": "2026-10-03T00:00:00+08:00", "observed_at": "2026-10-19T02:03:05Z"})
	a.Tables["meridian_route_grants"] = tableFixture(map[string]any{
		"id": "grant-example", "account_id": "account-example", "endpoint_id": "endpoint-example", "base_credential_id": "native-example", "route_credential_id": "route-example",
		"egress_node_id": "landing-example", "ipv4_egress_node_id": nil, "mode": "fixed", "hide_native": 1, "enabled": 0, "desired_revision": 9, "applied_revision": 8, "runtime_healthy": 0,
	})
	return a
}

func replaceCell(a *archive, tableName string, row int, column string, value cell) {
	t := a.Tables[tableName]
	index := slices.Index(t.Columns, column)
	if index < 0 {
		panic("missing test column")
	}
	t.Rows[row][index] = value
	a.Tables[tableName] = t
}

func TestAccountConversionPreservesIdentityAndIndependentCounters(t *testing.T) {
	m, err := importMaterial(completeEndpointArchiveFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	a := m.Plan.Accounts[0]
	if a.Account.ID != "account-example" || a.Account.DesiredRevision != 7 || a.Account.AppliedRevision != 6 || a.Account.Plan.TotalBytes != 9007199254740993 || a.Credentials[0].EntryID != "entry-example" {
		t.Fatal("identity/revision/quota changed")
	}
	if len(a.Credentials) != 2 || len(a.Grants) != 1 || a.Grants[0].ID != "grant-example" || a.Grants[0].DesiredRev != 9 || a.Grants[0].AppliedRev != 8 || a.Grants[0].Enabled || !a.Grants[0].HideNative {
		t.Fatal("disabled route or revisions changed")
	}
	if m.SubscriptionTokens[a.Account.ID] != "example-token" || m.ProtocolSecrets["native-example"] != "11111111-1111-4111-8111-111111111111" || m.HysteriaSecrets["native-example"] != "example-hy2" {
		t.Fatal("credentials regenerated")
	}
	if a.Usage[0].Baseline != 9007199254740000 || a.Usage[0].Observed != 9007199254740993 || a.Usage[1].Active {
		t.Fatal("ledger or disabled credential changed")
	}
	if m.TrafficCounters["native-example"].RawUploadBytes != 12345 || m.TrafficCounters["native-example"].UploadBytes != 123 || m.TrafficCounters["route-example"].StartedAt != "" {
		t.Fatal("raw totals substituted for period counters or missing observation invented")
	}
	if m.ResetSchedules[a.Account.ID].NextResetAt != "2026-11-19T00:00:00+08:00" {
		t.Fatal("cycle recalculated")
	}
	quota, err := glivela.ProjectQuota(a.Account.Plan, a.Usage)
	if err != nil || quota.UsedBytes != 4993 {
		t.Fatal("usage re-counted", err)
	}
}

func TestAccountConversionPreservesAnUnassignedAccount(t *testing.T) {
	a := completeEndpointArchiveFixture(t)
	for _, name := range []string{"meridian_credentials", "meridian_usage_watermarks", "meridian_line_usage", "meridian_route_grants"} {
		value := a.Tables[name]
		value.Rows = [][]cell{}
		a.Tables[name] = value
	}
	m, err := importMaterial(a)
	if err != nil || len(m.Plan.Accounts) != 1 || len(m.Plan.Accounts[0].Credentials) != 0 || len(m.TrafficCounters) != 0 || m.SubscriptionTokens["account-example"] != "example-token" {
		t.Fatal("unassigned account was dropped or initialized", err)
	}
}

func TestAccountConversionRejectsLossAndSubstitution(t *testing.T) {
	for name, change := range map[string]func(*archive){
		"missing watermark": func(a *archive) {
			x := a.Tables["meridian_usage_watermarks"]
			x.Rows = x.Rows[:1]
			a.Tables["meridian_usage_watermarks"] = x
		},
		"duplicate watermark": func(a *archive) {
			x := a.Tables["meridian_usage_watermarks"]
			x.Rows = append(x.Rows, x.Rows[0])
			a.Tables["meridian_usage_watermarks"] = x
		},
		"orphan account": func(a *archive) {
			replaceCell(a, "meridian_credentials", 0, "account_id", cell{Kind: "text", Text: "other-account"})
		},
		"unknown endpoint": func(a *archive) {
			replaceCell(a, "meridian_credentials", 0, "endpoint_id", cell{Kind: "text", Text: "other-endpoint"})
		},
		"wrong token": func(a *archive) {
			a.Secrets["token-secret"] = secretValue{Context: "meridian-account:account-example", Value: []byte("replacement-token")}
		},
		"wrong uuid": func(a *archive) {
			a.Secrets["native-secret"] = secretValue{Context: "meridian-credential:native-example", Value: []byte("33333333-3333-4333-8333-333333333333")}
		},
		"wrong aad": func(a *archive) {
			s := a.Secrets["native-secret"]
			s.Context = "meridian-credential:other"
			a.Secrets["native-secret"] = s
		},
		"nullable uuid": func(a *archive) { replaceCell(a, "meridian_credentials", 0, "protocol_secret_id", cell{Kind: "null"}) },
		"empty nullable reference": func(a *archive) {
			replaceCell(a, "meridian_credentials", 1, "hy2_auth_secret_id", cell{Kind: "text", Text: ""})
		},
		"rounded counter": func(a *archive) {
			replaceCell(a, "meridian_usage_watermarks", 0, "observed_bytes", cell{Kind: "real", Text: "9007199254740992"})
		},
		"reset integer overflow": func(a *archive) {
			replaceCell(a, "meridian_accounts", 0, "reset_days", cell{Kind: "integer", Text: "9223372036854775807"})
		},
		"reset policy maximum": func(a *archive) {
			replaceCell(a, "meridian_accounts", 0, "reset_days", cell{Kind: "integer", Text: "3651"})
		},
		"regressed watermark": func(a *archive) {
			replaceCell(a, "meridian_usage_watermarks", 0, "observed_bytes", cell{Kind: "integer", Text: "1"})
		},
		"wrong route credential": func(a *archive) {
			replaceCell(a, "meridian_route_grants", 0, "base_credential_id", cell{Kind: "text", Text: "route-example"})
		},
		"bad boolean": func(a *archive) { replaceCell(a, "meridian_accounts", 0, "enabled", cell{Kind: "integer", Text: "2"}) },
	} {
		t.Run(name, func(t *testing.T) {
			a := completeEndpointArchiveFixture(t)
			change(&a)
			if _, err := importMaterial(a); err == nil {
				t.Fatal("lossy or substituted state accepted")
			}
		})
	}
}

func writeArchiveFixture(t *testing.T, path string, a archive, key []byte) {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, nil, raw, []byte(archiveContext+a.SnapshotID))
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveToEncryptedControllerStaging(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "controller")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	transfer, storage := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)
	input, transferPath, storagePath := filepath.Join(dir, "archive.sealed"), filepath.Join(dir, "transfer.key"), filepath.Join(dir, "storage.key")
	for path, value := range map[string][]byte{transferPath: transfer, storagePath: storage} {
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a := completeEndpointArchiveFixture(t)
	writeArchiveFixture(t, input, a, transfer)
	args := []string{"-archive", input, "-snapshot", a.SnapshotID, "-state-directory", state, "-transfer-key", transferPath, "-storage-key", storagePath}
	// Account conversion alone would accept this input; endpoint preflight
	// must reject it before any pending account checkpoint is created.
	replaceCell(&a, "meridian_endpoints", 0, "listen_port", cell{Kind: "integer", Text: "65536"})
	writeArchiveFixture(t, input, a, transfer)
	if err := stageImportCommand(args); err == nil {
		t.Fatal("invalid endpoint did not fence staging")
	}
	if _, err := os.Lstat(filepath.Join(state, "business.pending.json")); !os.IsNotExist(err) {
		t.Fatal("preflight failure wrote account state")
	}
	replaceCell(&a, "meridian_endpoints", 0, "listen_port", cell{Kind: "integer", Text: "10443"})
	writeArchiveFixture(t, input, a, transfer)
	if err := stageImportCommand(args); err != nil {
		t.Fatal(err)
	}
	got, id, err := control.ReadStagedImport(state, storage)
	if err != nil || id != a.SnapshotID {
		t.Fatal("controller cannot reopen staged state", err)
	}
	var retained archive
	if json.Unmarshal(got.RetainedSource, &retained) != nil || !reflect.DeepEqual(retained, a) || got.SourceSHA256 != a.SourceSHA256 || len(got.Endpoints) != 1 || len(retained.Tables["meridian_route_health_events"].Rows) != 1 {
		t.Fatal("endpoint/source/history was omitted from the atomic checkpoint")
	}
	want, err := importMaterial(a)
	if err != nil {
		t.Fatal(err)
	}
	// Normalize optional JSON fields exactly as the durable format does.
	normalized, err := glivela.SealImportMaterial(want, transfer, a.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	want, err = glivela.OpenImportMaterial(normalized, transfer, a.SnapshotID)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("staging changed the business model", err)
	}
	path := filepath.Join(state, "business.pending.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("example-token")) {
		t.Fatal("plaintext persisted")
	}
	if _, _, err := control.ReadStagedImport(state, transfer); err == nil {
		t.Fatal("temporary transfer key retained")
	}
	if err := stageImportCommand(args); err != nil {
		t.Fatal("idempotent retry failed", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retry rewrote ledger")
	}
	replaceCell(&a, "meridian_line_usage", 0, "upload_bytes", cell{Kind: "integer", Text: "124"})
	writeArchiveFixture(t, input, a, transfer)
	if err := stageImportCommand(args); err == nil {
		t.Fatal("changed counters accepted under same snapshot")
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed retry changed original state")
	}
	if _, err := os.Lstat(filepath.Join(state, "accounts.active.json")); !os.IsNotExist(err) {
		t.Fatal("staging activated authority")
	}
	// Restore the original input so the lease, not the prior counter mismatch,
	// is the only remaining reason this otherwise valid retry can fail.
	replaceCell(&a, "meridian_line_usage", 0, "upload_bytes", cell{Kind: "integer", Text: "123"})
	writeArchiveFixture(t, input, a, transfer)
	unlock, err := control.LockDirectory(state)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := stageImportCommand(args); err == nil {
		t.Fatal("running controller lease bypassed")
	}
}

func TestRealLegacyAccountStagingFixture(t *testing.T) {
	dir := os.Getenv("GLIVELA_ACCOUNT_FIXTURE_DIR")
	if dir == "" {
		t.Skip("anonymous old-source account fixture not supplied")
	}
	transfer, err := privateFile(filepath.Join(dir, "transfer.key"), 32)
	if err != nil {
		t.Fatal("fixture transfer key unavailable")
	}
	defer clear(transfer)
	storage, err := privateFile(filepath.Join(dir, "storage.key"), 32)
	if err != nil {
		t.Fatal("fixture storage key unavailable")
	}
	defer clear(storage)
	sealed, err := privateFile(filepath.Join(dir, "legacy.sealed"), maxSnapshotBytes+64)
	if err != nil {
		t.Fatal("fixture archive unavailable")
	}
	a, err := openArchive(sealed, transfer, "actual-accounts-example")
	if err != nil {
		t.Fatal("fixture authentication failed")
	}
	m, err := importMaterial(a)
	if err != nil {
		t.Fatal("fixture conversion failed")
	}
	got, id, err := control.ReadStagedImport(filepath.Join(dir, "controller"), storage)
	if err != nil || id != a.SnapshotID {
		t.Fatal("fixture checkpoint unavailable")
	}
	canonical, err := glivela.SealImportMaterial(m, transfer, a.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := glivela.OpenImportMaterial(canonical, transfer, a.SnapshotID)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("real legacy records differ after staging")
	}
	var retained archive
	if json.Unmarshal(got.RetainedSource, &retained) != nil || !reflect.DeepEqual(retained, a) || len(got.Endpoints) != 1 || len(retained.Tables["meridian_route_health_events"].Rows) != 1 {
		t.Fatal("real endpoint or nonempty route history missing from atomic checkpoint")
	}
	credentials, routes := 0, 0
	for _, item := range got.Plan.Accounts {
		credentials += len(item.Credentials)
		routes += len(item.Grants)
		if item.Account.Plan.TotalBytes != 9007199254740993 || got.ResetSchedules[item.Account.ID].NextResetAt != "2026-11-19T00:00:00+08:00" {
			t.Fatal("real legacy quota or cycle changed")
		}
		for _, c := range item.Credentials {
			counters := got.TrafficCounters[c.ID]
			if counters.UploadBytes != 123 || counters.DownloadBytes != 456 || counters.ObservedAt != "2026-10-19T02:03:04.123456789Z" {
				t.Fatal("real legacy directional totals changed")
			}
		}
	}
	if len(got.Plan.Accounts) != 2 || credentials != 3 || routes != 1 {
		t.Fatal("incomplete real legacy inventory")
	}
	// Exercise the runtime controller's own loader, not only the offline
	// staging reader. No source database or transfer key enters the controller.
	controllerDir := filepath.Join(dir, "controller")
	unlock, err := control.LockDirectory(controllerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	controller, err := control.OpenStore(filepath.Join(controllerDir, "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.LoadBusiness(filepath.Join(dir, "storage.key")); err != nil {
		t.Fatal(err)
	}
	view := controller.Business()
	if view.State != "awaiting-handover" || view.SnapshotID != id || len(view.Accounts) != 2 || len(view.Endpoints) != 1 {
		t.Fatal("real source checkpoint did not reach owned controller inventory")
	}
	for i, item := range view.Accounts {
		if item.Account != got.Plan.Accounts[i].Account || !reflect.DeepEqual(item.Usage, got.Plan.Accounts[i].Usage) || item.Schedule != got.ResetSchedules[item.Account.ID] {
			t.Fatal("runtime loading changed source account or ledger")
		}
	}
	rawView, err := json.Marshal(view)
	if err != nil || !bytes.Contains(rawView, []byte(`"totalBytes":"9007199254740993"`)) || bytes.Contains(rawView, []byte("retainedSource")) || bytes.Contains(rawView, []byte("protocolSecrets")) {
		t.Fatal("runtime view lost precision or disclosed migration secrets")
	}
}
