package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

func TestPurgeRetiredHistoryPreservesV2LedgerAndRetries(t *testing.T) {
	for _, format := range []string{"v1", "v2"} {
		t.Run(format, func(t *testing.T) {
			ctx := context.Background()
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			state, center := filepath.Join(root, "state"), filepath.Join(root, "center")
			for _, dir := range []string{state, center} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			read := func(path string) []byte {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			write(filepath.Join(state, "nodes.json"), []byte("[]"))
			const target = "retired-history-only"
			a := completeEndpointArchiveFixture(t)
			m, err := importMaterial(a)
			if err != nil {
				t.Fatal(err)
			}
			// Detach live maps from the retained-source fixture before adding retired history.
			copied, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			m = glivela.ImportMaterial{}
			if err = json.Unmarshal(copied, &m); err != nil {
				t.Fatal(err)
			}
			// Only the retained archive contains this retired host. Live routes remain intact.
			a.References.Nodes[target] = glivela.ImportNode{Name: "Retired-only-private-host", PreviousStatus: "disabled"}
			a.Tables["task_events"] = tableFixture(map[string]any{"id": "retired-event", "agent_id": target})
			m.RetainedSource, err = json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			m.RetiredLandings = map[string]glivela.RetiredLanding{target: {CertificateID: glivela.Identity("retired"), Revision: 1}}
			storage, transfer := bytes.Repeat([]byte{31}, 32), bytes.Repeat([]byte{32}, 32)
			sealed, err := glivela.SealImportMaterial(m, transfer, a.SnapshotID)
			if err != nil {
				t.Fatal(err)
			}
			if err = control.StageImport(state, a.SnapshotID, sealed, transfer, storage); err != nil {
				t.Fatal(err)
			}
			ownership := glivela.BusinessOwnership{SourceSHA256: m.SourceSHA256, CaptureSHA256: glivela.Identity("capture-fixture"), PreviousWriterID: strings.Repeat("a", 64), StoppedAt: "2026-10-19T02:00:00Z", CapturedAt: "2026-10-19T02:01:00Z"}
			if err = control.AdoptStagedBusiness(state, a.SnapshotID, ownership, storage); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(state, "business.key"), storage)
			store, err := control.OpenStore(filepath.Join(state, "nodes.json"))
			if err != nil {
				t.Fatal(err)
			}
			if format == "v2" {
				if err = store.LoadBusiness(filepath.Join(state, "business.key")); err != nil {
					t.Fatal(err)
				}
			}
			before, _, _, err := control.ReadOwnedBusinessForHistory(state, storage)
			if err != nil {
				t.Fatal(err)
			}
			nodes := read(filepath.Join(state, "nodes.json"))
			write(filepath.Join(center, "center.key"), bytes.Repeat([]byte{7}, 32))
			db, err := sql.Open("sqlite", filepath.Join(center, "center.db"))
			if err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{
				`CREATE TABLE retired_proxy_business(id INTEGER PRIMARY KEY)`, `INSERT INTO retired_proxy_business VALUES(1)`,
				`CREATE TABLE secrets(id TEXT PRIMARY KEY,sealed BLOB)`,
				`CREATE TABLE meridian_subscription_snapshots(account_id TEXT,secret_id TEXT)`,
				`CREATE TABLE meridian_cutover(import_secret_id TEXT)`,
				`CREATE TABLE deployments(id TEXT PRIMARY KEY,secret_id TEXT)`,
				`CREATE TABLE application_commands(id TEXT PRIMARY KEY,result_secret_id TEXT)`,
				`CREATE TABLE application_secrets(application_id TEXT,secret_id TEXT)`,
				`CREATE TABLE task_executions(id TEXT PRIMARY KEY,sealed_task BLOB,sealed_result BLOB)`,
				`CREATE TABLE execution_events(id INTEGER PRIMARY KEY,execution_id TEXT)`,
				`CREATE TABLE task_events(id TEXT PRIMARY KEY,agent_id TEXT)`,
				`CREATE TABLE node_diagnostic_checks(id TEXT PRIMARY KEY,agent_id TEXT)`,
				`CREATE TABLE ip_quality_checks(id TEXT PRIMARY KEY,agent_id TEXT)`,
				`INSERT INTO task_events VALUES('retired-event','retired-history-only'),('live-event','entry-host-example')`,
			} {
				if _, err = db.Exec(statement); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(filepath.Join(center, "center.db"), 0600); err != nil {
				t.Fatal(err)
			}
			options := historyPurgeOptions{directory: state, center: center, nodes: target, audit: filepath.Join(root, "audit.json")}
			if err = purgeStoppedHistory(ctx, options); err != nil {
				t.Fatal(err)
			}
			after, _, _, err := control.ReadOwnedBusinessForHistory(state, storage)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(after.RetainedSource, []byte("Retired-only-private-host")) || bytes.Contains(after.RetainedSource, []byte("retired-event")) {
				t.Fatal("retired archive history remains")
			}
			var retained archive
			if err = json.Unmarshal(after.RetainedSource, &retained); err != nil {
				t.Fatal(err)
			}
			if _, ok := retained.References.Nodes["entry-host-example"]; !ok {
				t.Fatal("unrelated history removed")
			}
			before.RetainedSource = nil
			after.RetainedSource = nil
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(after)
			if !bytes.Equal(beforeJSON, afterJSON) || !bytes.Equal(nodes, read(filepath.Join(state, "nodes.json"))) {
				t.Fatal("live identity, route or accounting changed")
			}
			ledger := read(filepath.Join(state, "business.json"))
			var envelope struct {
				Version int `json:"version"`
			}
			if json.Unmarshal(ledger, &envelope) != nil || envelope.Version != 2 {
				t.Fatal("maintenance downgraded live ledger")
			}
			if err = purgeStoppedHistory(ctx, options); err != nil {
				t.Fatal("idempotent retry", err)
			}
			if !bytes.Equal(ledger, read(filepath.Join(state, "business.json"))) {
				t.Fatal("retry rewrote accounting ledger")
			}
			archives, err := filepath.Glob(filepath.Join(state, "business.archive-*.json"))
			if err != nil || len(archives) != 1 {
				t.Fatal("obsolete archive not cleaned", err)
			}
			db, err = sql.Open("sqlite", filepath.Join(center, "center.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			if err = db.QueryRow(`SELECT count(*) FROM task_events WHERE id='live-event'`).Scan(&count); err != nil || count != 1 {
				t.Fatal("live Center history changed", err)
			}
			if err = db.QueryRow(`SELECT count(*) FROM task_events WHERE id='retired-event'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("retired Center history remains", err)
			}
			if purgeHistoryCommand(ctx, []string{"-state-directory", state, "-center-directory", center, "-node-ids", target}) == nil {
				t.Fatal("CLI allowed missing stopped-writer confirmation")
			}
		})
	}
}
