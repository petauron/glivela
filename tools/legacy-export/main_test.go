package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fixture(t *testing.T) (string, []byte, *sql.DB) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "frozen.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("PRAGMA user_version=113")
	exec("CREATE TABLE storage_key_binding(id INTEGER PRIMARY KEY,sealed BLOB)")
	exec("CREATE TABLE secrets(id TEXT PRIMARY KEY,sealed BLOB)")
	exec("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT)")
	exec("CREATE TABLE applications(id TEXT PRIMARY KEY,name TEXT,node_id TEXT,runtime TEXT,status TEXT,app_key TEXT)")
	for _, name := range businessTables {
		columns := "id TEXT PRIMARY KEY,payload BLOB,optional TEXT,counter INTEGER"
		if name == "meridian_accounts" {
			columns += ",subscription_token_secret_id TEXT REFERENCES secrets(id)"
		}
		if name == "meridian_subscription_snapshots" {
			columns += ",account_id TEXT,secret_id TEXT REFERENCES secrets(id)"
		}
		if name == "meridian_endpoints" {
			columns += ",application_id TEXT,service_id TEXT"
		}
		if name == "landing_client_grants" {
			columns += ",application_id TEXT,service_id TEXT,landing_node_id TEXT"
		}
		exec(`CREATE TABLE "` + name + `"(` + columns + `)`)
	}
	// Existing schema-113 fixture: retain empty historical tables now consumed
	// by the exporter. No additional scenario or test environment is introduced.
	for _, statement := range []string{
		"CREATE TABLE application_commands(id TEXT PRIMARY KEY,application_id TEXT,kind TEXT,result_secret_id TEXT)",
		"CREATE TABLE deployments(id TEXT PRIMARY KEY,application_id TEXT,secret_id TEXT)",
		"CREATE TABLE node_diagnostic_checks(id TEXT PRIMARY KEY,agent_id TEXT,kind TEXT)",
		"CREATE TABLE ip_quality_checks(id TEXT PRIMARY KEY,agent_id TEXT)",
		"CREATE TABLE task_events(id TEXT PRIMARY KEY,task_id TEXT,agent_id TEXT,kind TEXT)",
		"CREATE TABLE task_executions(id TEXT PRIMARY KEY,task_id TEXT,agent_id TEXT,kind TEXT,sealed_task BLOB,sealed_result BLOB)",
		"CREATE TABLE execution_events(id INTEGER PRIMARY KEY,execution_id TEXT)",
	} {
		exec(statement)
	}
	key := bytes.Repeat([]byte{7}, 32)
	exec("INSERT INTO storage_key_binding VALUES(1,?)", sealLegacy(t, key, []byte("vastora-database-key-binding-v1"), "database-key-binding:center:v1"))
	exec("INSERT INTO secrets VALUES(?,?)", "token-example", sealLegacy(t, key, []byte("test-token-only"), "meridian-account:account-example"))
	exec("INSERT INTO secrets VALUES(?,?)", "snapshot-example", sealLegacy(t, key, []byte("synthetic-subscription"), "meridian-subscription-snapshot:account-example"))
	exec("INSERT INTO meridian_accounts VALUES(?,?,?,?,?)", "account-example", []byte{}, nil, int64(9007199254740993), "token-example")
	exec("INSERT INTO meridian_subscription_snapshots VALUES(?,?,?,?,?,?)", "snapshot-example", []byte{0, 1}, "", int64(0), "account-example", "snapshot-example")
	// Unrelated application credentials must not leave the frozen backup.
	exec("INSERT INTO secrets VALUES('unrelated',?)", []byte("not-even-valid-ciphertext"))
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path, key, db
}

func sealLegacy(t *testing.T, key, value []byte, aad string) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(nonce, nonce, value, []byte(aad))
}

func TestExportPreservesRecordsWithoutChangingBackup(t *testing.T) {
	path, key, db := fixture(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	transfer := bytes.Repeat([]byte{8}, 32)
	for name, value := range map[string][]byte{"source.key": key, "transfer.key": transfer} {
		if err := os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "export.sealed")
	if err := export(context.Background(), path, filepath.Join(dir, "source.key"), filepath.Join(dir, "transfer.key"), "snapshot-example", out); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("backup changed", err)
	}
	sealed, err := privateFile(out, maxSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("test-token-only")) || bytes.Contains(sealed, key) {
		t.Fatal("plaintext credential escaped")
	}
	block, _ := aes.NewCipher(transfer)
	gcm, _ := cipher.NewGCMWithRandomNonce(block)
	raw, err := gcm.Open(nil, nil, sealed, []byte(archiveContext+"snapshot-example"))
	if err != nil {
		t.Fatal(err)
	}
	var a archive
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(before)
	if a.Version != 1 || a.Schema != 113 || a.SourceSHA256 != hex.EncodeToString(sum[:]) || len(a.Tables) != len(archiveTables) {
		t.Fatal("archive inventory differs")
	}
	row := a.Tables["meridian_accounts"].Rows[0]
	if row[0].Text != "account-example" || row[1].Kind != "blob" || row[2].Kind != "null" || row[3].Text != "9007199254740993" {
		t.Fatal("identity/storage classes/counter changed")
	}
	if len(a.Secrets) != 2 || string(a.Secrets["token-example"].Value) != "test-token-only" || string(a.Secrets["snapshot-example"].Value) != "synthetic-subscription" {
		t.Fatal("secret scope or identity changed")
	}
	if _, err := gcm.Open(nil, nil, sealed, []byte(archiveContext+"different-snapshot")); err == nil {
		t.Fatal("snapshot substitution accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := gcm.Open(nil, nil, sealed, []byte(archiveContext+"snapshot-example")); err == nil {
		t.Fatal("tampered export accepted")
	}
	if err := export(context.Background(), path, filepath.Join(dir, "source.key"), filepath.Join(dir, "transfer.key"), "snapshot-example", out); err == nil {
		t.Fatal("overwrote existing archive")
	}
}

func TestExportRejectsUnverifiedSources(t *testing.T) {
	for name, query := range map[string]string{
		"schema":             "PRAGMA user_version=116",
		"missing table":      "DROP TABLE meridian_route_grants",
		"new business table": "CREATE TABLE meridian_unreviewed(id TEXT)",
		"orphan":             "UPDATE meridian_accounts SET subscription_token_secret_id='missing'",
		"ciphertext":         "UPDATE secrets SET sealed=x'00' WHERE id='token-example'",
		"unknown secret":     "ALTER TABLE meridian_accounts ADD COLUMN unknown_secret_id TEXT DEFAULT 'token-example'",
	} {
		t.Run(name, func(t *testing.T) {
			_, key, db := fixture(t)
			if _, err := db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := readArchive(context.Background(), db, key); err == nil {
				t.Fatal("unverified source accepted")
			}
		})
	}
	t.Run("wrong key", func(t *testing.T) {
		_, _, db := fixture(t)
		if _, err := readArchive(context.Background(), db, bytes.Repeat([]byte{9}, 32)); err == nil {
			t.Fatal("wrong key accepted")
		}
	})
}

func TestPrivateFilesAndSidecars(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("synthetic"), 0644); err != nil {
		t.Fatal(err)
	}
	// A secure caller umask may have created this as 0600. The negative case
	// must actually be public, not merely request public creation permissions.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := privateFile(path, 32); err == nil {
		t.Fatal("public input accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateFile(link, 32); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		sidecar := path + suffix
		if err := os.WriteFile(sidecar, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := standalone(path); err == nil {
			t.Fatal("live sidecar accepted")
		}
		if err := os.Remove(sidecar); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeNewPrivate(path, []byte("replacement")); err == nil {
		t.Fatal("existing path overwritten")
	}
	got, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(got, []byte("synthetic")) {
		t.Fatal("original file changed")
	}
}

// Opt-in integration fixture: generated by the retained schema-113 Vastora
// source using synthetic records only. Never point this at production data.
func TestRealLegacySchemaFixture(t *testing.T) {
	dir := os.Getenv("GLIVELA_LEGACY_FIXTURE_DIR")
	if dir == "" {
		t.Skip("synthetic old-source fixture not supplied")
	}
	sealed, err := privateFile(filepath.Join(dir, "actual.sealed"), maxSnapshotBytes)
	if err != nil {
		t.Fatal("private fixture archive unavailable")
	}
	key, err := privateFile(filepath.Join(dir, "transfer.key"), 32)
	if err != nil {
		t.Fatal("private fixture key unavailable")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("invalid fixture key")
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := gcm.Open(nil, nil, sealed, []byte(archiveContext+"snapshot-actual-schema"))
	if err != nil {
		t.Fatal("fixture authentication failed")
	}
	defer clear(raw)
	var a archive
	if json.Unmarshal(raw, &a) != nil || a.Version != 1 || a.Schema != 113 {
		t.Fatal("fixture format differs")
	}
	accounts := a.Tables["meridian_accounts"]
	if len(accounts.Rows) != 1 || textAt(accounts, accounts.Rows[0], "id") != "account-example" {
		t.Fatal("fixture account identity differs")
	}
	row := accounts.Rows[0]
	for column, want := range map[string]string{"total_bytes": "9007199254740993", "reset_days": "30", "next_reset_at": "2026-11-19T00:00:00Z", "last_reset_at": "2026-10-19T00:00:00Z"} {
		found := false
		for i, name := range accounts.Columns {
			if name == column {
				found = row[i].Text == want
			}
		}
		if !found {
			t.Fatal("fixture ledger or schedule differs")
		}
	}
	if len(a.Secrets) != 1 || string(a.Secrets["token-example"].Value) != "synthetic-token-only" {
		t.Fatal("fixture secret scope differs")
	}
}
