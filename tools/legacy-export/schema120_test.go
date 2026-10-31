package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

func TestSchema120PrivateRehearsal(t *testing.T) {
	dir := os.Getenv("GLIVELA_SCHEMA120_FIXTURE_DIR")
	if dir == "" {
		t.Skip("optional private frozen schema-120 backup")
	}
	key, err := privateFile(filepath.Join(dir, "transfer.key"), 32)
	if err != nil {
		t.Fatal("private transfer key unavailable")
	}
	defer clear(key)
	private, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "center.db")
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal("private source unavailable")
	}
	digest := sha256.Sum256(before)
	clear(before)
	output := filepath.Join(private, "archive.sealed")
	if err := export(context.Background(), input, filepath.Join(dir, "source.key"), filepath.Join(dir, "transfer.key"), "schema120-rehearsal", output); err != nil {
		t.Fatal("private export failed")
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != digest {
		t.Fatal("source changed")
	}
	clear(after)
	sealed, err := privateFile(output, maxSnapshotBytes+64)
	if err != nil {
		t.Fatal("private archive unavailable")
	}
	a, err := openArchive(sealed, key, "schema120-rehearsal")
	if err != nil {
		t.Fatal("archive validation failed", err)
	}
	if a.SourceSHA256 != hex.EncodeToString(digest[:]) || a.Schema != 120 {
		t.Fatal("source identity changed")
	}
	u := url.URL{Scheme: "file", Path: input, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal("source unavailable")
	}
	defer db.Close()
	for _, name := range append(slices.Clone(businessTables), "glivela_pilot_checkpoint") {
		want := a.Tables[name]
		got, err := readTable(context.Background(), db, name)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("retained source table differs")
		}
	}
	m, err := importMaterial(a)
	if err != nil {
		t.Fatal("material conversion failed", err)
	}
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	storage := bytes.Repeat([]byte{23}, 32)
	transfer, err := glivela.SealImportMaterial(m, key, a.SnapshotID)
	if err != nil {
		t.Fatal("material sealing failed", err)
	}
	if err := control.StageImport(state, a.SnapshotID, transfer, key, storage); err != nil {
		t.Fatal("staging failed", err)
	}
	got, id, err := control.ReadStagedImport(state, storage)
	if err != nil || id != a.SnapshotID {
		t.Fatal("staged import unavailable")
	}
	var retained archive
	if json.Unmarshal(got.RetainedSource, &retained) != nil || !reflect.DeepEqual(retained, a) {
		t.Fatal("retained source changed")
	}
	verifySchema120Business(t, a, got)
	if err := os.WriteFile(filepath.Join(private, "storage.key"), storage, 0600); err != nil {
		t.Fatal(err)
	}
	unlock, err := control.LockDirectory(state)
	if err != nil {
		t.Fatal("controller lock failed")
	}
	defer unlock()
	controller, err := control.OpenStore(filepath.Join(state, "nodes.json"))
	if err != nil {
		t.Fatal("controller store failed")
	}
	if controller.LoadBusiness(filepath.Join(private, "storage.key")) != nil {
		t.Fatal("controller cannot load pending data")
	}
	view := controller.Business()
	if view.State != "awaiting-handover" || view.SnapshotID != id || len(view.Accounts) != len(got.Plan.Accounts) || len(view.Endpoints) != len(got.Endpoints) || got.Ownership != nil {
		t.Fatal("offline load activated or lost business data")
	}
	for i, item := range view.Accounts {
		if item.Account != got.Plan.Accounts[i].Account || !reflect.DeepEqual(item.Usage, got.Plan.Accounts[i].Usage) || item.Schedule != got.ResetSchedules[item.Account.ID] {
			t.Fatal("controller account ledger differs")
		}
	}

	t.Logf("retained accounts=%d credentials=%d watermarks=%d endpoints=%d routes=%d checkpoints=%d", len(a.Tables["meridian_accounts"].Rows), len(a.Tables["meridian_credentials"].Rows), len(a.Tables["meridian_usage_watermarks"].Rows), len(a.Tables["meridian_endpoints"].Rows), len(a.Tables["meridian_route_grants"].Rows), len(a.Tables["glivela_pilot_checkpoint"].Rows))
}

func pilotArchiveFixture(t *testing.T) archive {
	t.Helper()
	a := completeEndpointArchiveFixture(t)
	a.Schema = 120
	a.Tables["glivela_pilot_checkpoint"] = tableFixture(map[string]any{"endpoint_id": "endpoint-example", "checkpoint_json": `{"EntryID":"entry-example","StartedAt":"2026-10-19T01:00:00Z","SampledAt":"2026-10-19T02:03:04Z","Raw":[{"credentialId":"native-example","upBytes":12,"downBytes":23},{"credentialId":"route-example","upBytes":30,"downBytes":20}],"Totals":[{"credentialId":"native-example","upBytes":12345,"downBytes":23456},{"credentialId":"route-example","upBytes":3000,"downBytes":2000}]}`})
	return a
}

func TestSchema120PilotCountersPreserveLedger(t *testing.T) {
	a := pilotArchiveFixture(t)
	oldArchive := a
	oldArchive.Schema = 113
	old, err := importMaterial(oldArchive)
	if err != nil {
		t.Fatal(err)
	}
	m, err := importMaterial(a)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(old.Plan, m.Plan) || !reflect.DeepEqual(old.Endpoints, m.Endpoints) || !reflect.DeepEqual(old.SubscriptionTokens, m.SubscriptionTokens) || !reflect.DeepEqual(old.ProtocolSecrets, m.ProtocolSecrets) || !reflect.DeepEqual(old.ResetSchedules, m.ResetSchedules) {
		t.Fatal("pilot conversion changed accounting, policy or identity")
	}
	for id, want := range old.TrafficCounters {
		got := m.TrafficCounters[id]
		if got.UploadBytes != want.UploadBytes || got.DownloadBytes != want.DownloadBytes || got.WatermarkObservedAt != want.WatermarkObservedAt || got.StartedAt != "2026-10-19T01:00:00Z" || got.ObservedAt != "2026-10-19T02:03:04Z" {
			t.Fatal("lifetime ledger or process epoch changed")
		}
	}
	if m.TrafficCounters["native-example"].RawUploadBytes != 12 || m.TrafficCounters["native-example"].RawDownloadBytes != 23 {
		t.Fatal("lifetime totals treated as physical counters")
	}
	for name, mutate := range map[string]func(*archive){
		"missing table": func(a *archive) { delete(a.Tables, "glivela_pilot_checkpoint") },
		"mismatched ledger": func(a *archive) {
			replaceCell(a, "meridian_usage_watermarks", 0, "raw_up_bytes", cell{Kind: "integer", Text: "12346"})
		},
		"wrong entry": func(a *archive) {
			replaceCell(a, "glivela_pilot_checkpoint", 0, "checkpoint_json", cell{Kind: "text", Text: `{"EntryID":"other"}`})
		},
		"incomplete sample": func(a *archive) {
			r := a.Tables["glivela_pilot_checkpoint"]
			i := slices.Index(r.Columns, "checkpoint_json")
			r.Rows[0][i].Text = strings.Replace(r.Rows[0][i].Text, `{"credentialId":"route-example","upBytes":30,"downBytes":20}`, `{"credentialId":"native-example","upBytes":30,"downBytes":20}`, 1)
			a.Tables["glivela_pilot_checkpoint"] = r
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := pilotArchiveFixture(t)
			mutate(&a)
			if _, err := importMaterial(a); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
}

func TestSchema120NativeReferenceAndTarget(t *testing.T) {
	for _, tc := range []struct {
		name         string
		schema       int
		runtime, key string
		want         bool
	}{
		{"native", 120, "host", "vastora-official/glivela-entry", true},
		{"old schema", 116, "host", "vastora-official/glivela-entry", false},
		{"wrong runtime", 120, "docker", "vastora-official/glivela-entry", false},
		{"unrelated app", 120, "host", "example/unrelated", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, a := referenceFixture(t)
			a.Schema = tc.schema
			if tc.schema == 120 {
				a.Tables["glivela_pilot_checkpoint"] = pilotArchiveFixture(t).Tables["glivela_pilot_checkpoint"]
			}
			if _, err := db.Exec("UPDATE applications SET app_key=?,runtime=? WHERE id='entry-example'", tc.key, tc.runtime); err != nil {
				t.Fatal(err)
			}
			refs, err := readReferences(context.Background(), db, a)
			if !tc.want {
				if err == nil {
					t.Fatal("unreviewed native reference accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			a.References = refs
			replaceCell(&a, "meridian_endpoints", 0, "target_ip", cell{Kind: "text"})
			replaceCell(&a, "meridian_endpoints", 0, "listen_address", cell{Kind: "text", Text: "2606:4700::1111"})
			m, err := importMaterial(a)
			if err != nil {
				t.Fatal(err)
			}
			if m.Endpoints[0].TargetIP != "" || m.Endpoints[0].Reality.Target != "www.example.com:443" {
				t.Fatal("native DNS target changed")
			}
			checkpoint := a.Tables["glivela_pilot_checkpoint"]
			a.Tables["glivela_pilot_checkpoint"] = tableFixture()
			if _, err := importMaterial(a); err == nil {
				t.Fatal("native entry accepted without its physical counter checkpoint")
			}
			a.Tables["glivela_pilot_checkpoint"] = checkpoint
			a.Schema = 116
			if _, err := importMaterial(a); err == nil {
				t.Fatal("legacy target pin requirement bypassed")
			}
		})
	}
}

func TestSchema120ExportRequiresCheckpointTable(t *testing.T) {
	_, key, db := fixture(t)
	if _, err := db.Exec("PRAGMA user_version=120"); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchive(context.Background(), db, key); err == nil {
		t.Fatal("missing pilot table silently omitted")
	}
	if _, err := db.Exec("CREATE TABLE glivela_pilot_checkpoint(id INTEGER PRIMARY KEY,endpoint_id TEXT,checkpoint_json BLOB,updated_at TEXT)"); err != nil {
		t.Fatal(err)
	}
	a, err := readArchive(context.Background(), db, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Tables["glivela_pilot_checkpoint"]; !ok || a.Schema != 120 {
		t.Fatal("schema checkpoint not retained")
	}
	if _, err := db.Exec("CREATE TABLE glivela_future(id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchive(context.Background(), db, key); err == nil {
		t.Fatal("unreviewed native business table silently omitted")
	}
	for _, version := range []int{117, 118, 119, 121} {
		if supportedSourceSchema(version) {
			t.Fatal("unreviewed schema accepted")
		}
	}
}

// Compare the executable business inventory against the original frozen rows,
// in addition to retaining every original row/cell in the encrypted checkpoint.
// No private identifiers or values are printed on mismatch.
func verifySchema120Business(t *testing.T, a archive, m glivela.ImportMaterial) {
	t.Helper()
	rows := func(name string) []*record {
		r, err := records(a, name)
		if err != nil {
			t.Fatal("source rows unavailable")
		}
		return r
	}
	accounts := map[string]glivela.ImportAccount{}
	credentials := map[string]glivela.Credential{}
	usage := map[string]glivela.UsageMember{}
	for _, item := range m.Plan.Accounts {
		accounts[item.Account.ID] = item
		for _, c := range item.Credentials {
			credentials[c.ID] = c
		}
		for _, u := range item.Usage {
			usage[u.CredentialID] = u
		}
	}
	if len(accounts) != len(rows("meridian_accounts")) || len(credentials) != len(rows("meridian_credentials")) || len(usage) != len(rows("meridian_usage_watermarks")) {
		t.Fatal("business inventory differs")
	}
	for _, r := range rows("meridian_accounts") {
		id := r.text("id")
		got := accounts[id].Account
		if got.DisplayName != r.text("display_name") || got.Plan.TotalBytes != r.integer("total_bytes") || got.Plan.ExpiryTime != r.integer("expiry_time") || got.Plan.ResetDays != int(r.integer("reset_days")) || got.Plan.Enabled != r.boolean("enabled") || m.SubscriptionTokens[id] != string(a.Secrets[r.text("subscription_token_secret_id")].Value) || m.ResetSchedules[id].NextResetAt != r.text("next_reset_at") || m.ResetSchedules[id].LastResetAt != r.text("last_reset_at") {
			t.Fatal("account, token or billing cycle changed")
		}
	}
	entries := map[string]string{}
	for _, e := range rows("meridian_endpoints") {
		entries[e.text("id")] = e.text("application_id")
	}
	for _, r := range rows("meridian_credentials") {
		id := r.text("id")
		c := credentials[id]
		if c.AccountID != r.text("account_id") || c.EntryID != entries[r.text("endpoint_id")] || c.Kind != glivela.CredentialKind(r.text("kind")) || c.Enabled != r.boolean("enabled") || c.Identity != r.text("identity_sha256") || m.ProtocolSecrets[id] != string(a.Secrets[r.text("protocol_secret_id")].Value) || m.HysteriaSecrets[id] != string(a.Secrets[r.optionalText("hy2_auth_secret_id")].Value) {
			t.Fatal("subscription credential changed")
		}
	}
	for _, r := range rows("meridian_usage_watermarks") {
		id := r.text("credential_id")
		u := usage[id]
		if u.Baseline != r.integer("baseline_bytes") || u.Observed != r.integer("observed_bytes") || m.TrafficCounters[id].WatermarkObservedAt != r.text("observed_at") {
			t.Fatal("traffic ledger changed")
		}
	}
	for _, r := range rows("meridian_line_usage") {
		c := m.TrafficCounters[r.text("credential_id")]
		if c.UploadBytes != r.integer("upload_bytes") || c.DownloadBytes != r.integer("download_bytes") {
			t.Fatal("directional accounting totals changed")
		}
	}
	for _, r := range rows("glivela_pilot_checkpoint") {
		var p struct {
			StartedAt, SampledAt time.Time
			Raw                  []glivela.CounterSnapshot
		}
		if json.Unmarshal(r.jsonBytes("checkpoint_json"), &p) != nil {
			t.Fatal("invalid source checkpoint")
		}
		for _, raw := range p.Raw {
			c := m.TrafficCounters[raw.CredentialID]
			if c.RawUploadBytes != raw.UpBytes || c.RawDownloadBytes != raw.DownBytes || c.StartedAt != p.StartedAt.Format(time.RFC3339Nano) || c.ObservedAt != p.SampledAt.Format(time.RFC3339Nano) {
				t.Fatal("runtime counter baseline changed")
			}
		}
	}
	for _, r := range rows("meridian_endpoints") {
		var got *glivela.ImportEndpoint
		for i := range m.Endpoints {
			if m.Endpoints[i].Reality.ID == r.text("id") {
				got = &m.Endpoints[i]
				break
			}
		}
		if got == nil || got.Reality.EntryID != r.text("application_id") || got.Reality.AdvertiseHost != r.text("advertise_host") || got.Reality.Target != r.text("target") || got.TargetIP != r.text("target_ip") || got.TotalBytes != r.integer("total_bytes") || got.UsedBytes != r.integer("used_bytes") || got.ResetDay != int(r.integer("reset_day")) || got.Reality.PrivateKey != string(a.Secrets[r.text("private_key_secret_id")].Value) {
			t.Fatal("endpoint, quota or key changed")
		}
	}
}
