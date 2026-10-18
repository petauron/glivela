// This one-time offline tool is a separate module. SQLite is never imported
// by Glivela's controller or node, and exporting does not transfer authority.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const supportedSchema = 113
const maxSnapshotBytes = 128 << 20
const archiveContext = "glivela-offline-legacy-export-v1:"

var businessTables = []string{
	"meridian_cutover", "meridian_endpoints", "meridian_accounts",
	"meridian_credentials", "meridian_route_grants", "meridian_line_usage",
	"meridian_usage_watermarks", "meridian_subscription_snapshots",
	"meridian_deployments", "meridian_route_health_events",
	"landing_server_states", "landing_proxy_states", "landing_proxy_retirements",
	"landing_client_grants", "landing_client_blocks", "node_egress_policies",
}

// Storage classes and decimal integer strings avoid rounding counters >2^53.
type cell struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
	Blob []byte `json:"blob,omitempty"`
}
type table struct {
	Columns []string `json:"columns"`
	Rows    [][]cell `json:"rows"`
}
type secretValue struct {
	Context string `json:"context"`
	Value   []byte `json:"value"`
}
type archive struct {
	Version      int                    `json:"version"`
	Schema       int                    `json:"sourceSchema"`
	SnapshotID   string                 `json:"snapshotId"`
	SourceSHA256 string                 `json:"sourceSha256"`
	Tables       map[string]table       `json:"tables"`
	Secrets      map[string]secretValue `json:"secrets"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "stage" {
		if stageImportCommand(os.Args[2:]) != nil {
			fmt.Fprintln(os.Stderr, "offline business staging failed; existing authority unchanged")
			os.Exit(1)
		}
		fmt.Println("business data staged; authority remains unchanged")
		return
	}
	database := flag.String("database", "", "absolute frozen standalone backup path")
	sourceKey := flag.String("source-key", "", "private Center key file from the same backup")
	transferKey := flag.String("transfer-key", "", "independent private 32-byte transfer key file")
	snapshot := flag.String("snapshot", "", "unique snapshot identifier")
	output := flag.String("output", "", "new private encrypted archive path")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if flag.NArg() != 0 || export(ctx, *database, *sourceKey, *transferKey, *snapshot, *output) != nil {
		// SQL/driver errors can contain private values; never print them.
		fmt.Fprintln(os.Stderr, "offline export failed; no authority was transferred")
		os.Exit(1)
	}
	fmt.Println("encrypted offline export written; authority remains unchanged")
}

func safeParent(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute path required")
	}
	for p := filepath.Dir(path); p != "/"; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil || !i.IsDir() || i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
			return errors.New("unsafe parent")
		}
	}
	return nil
}

func privateFile(path string, limit int64) ([]byte, error) {
	if err := safeParent(path); err != nil {
		return nil, err
	}
	i, err := os.Lstat(path)
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > limit {
		return nil, errors.New("unsafe file")
	}
	return os.ReadFile(path)
}

func standalone(path string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return errors.New("backup has sidecars")
		}
	}
	return nil
}

func export(ctx context.Context, path, sourceKeyPath, transferKeyPath, snapshot, output string) error {
	if len(snapshot) < 1 || len(snapshot) > 128 || strings.IndexFunc(snapshot, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) >= 0 {
		return errors.New("invalid snapshot")
	}
	key, err := privateFile(sourceKeyPath, 32)
	if err != nil || len(key) != 32 {
		return errors.New("invalid source key")
	}
	defer clear(key)
	transfer, err := privateFile(transferKeyPath, 32)
	if err != nil || len(transfer) != 32 || slices.Equal(key, transfer) {
		return errors.New("independent transfer key required")
	}
	defer clear(transfer)
	if err := standalone(path); err != nil {
		return err
	}
	before, err := privateFile(path, maxSnapshotBytes)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(before)
	clear(before)
	// Immutable mode must only read a frozen standalone backup, never live DBs.
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	a, err := readArchive(ctx, db, key)
	if err != nil {
		return err
	}
	defer func() {
		for _, secret := range a.Secrets {
			clear(secret.Value)
		}
	}()
	a.Version, a.SnapshotID, a.SourceSHA256 = 1, snapshot, hex.EncodeToString(sum[:])
	after, err := privateFile(path, maxSnapshotBytes)
	if err != nil {
		return err
	}
	afterSum := sha256.Sum256(after)
	clear(after)
	if sum != afterSum {
		return errors.New("source changed")
	}
	if err := standalone(path); err != nil {
		return err
	}
	raw, err := json.Marshal(a)
	if err != nil || len(raw) > maxSnapshotBytes {
		return errors.New("archive too large")
	}
	defer clear(raw)
	block, err := aes.NewCipher(transfer)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return err
	}
	return writeNewPrivate(output, gcm.Seal(nil, nil, raw, []byte(archiveContext+snapshot)))
}

func readArchive(ctx context.Context, db *sql.DB, key []byte) (archive, error) {
	a := archive{Tables: map[string]table{}, Secrets: map[string]secretValue{}}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&a.Schema); err != nil || a.Schema != supportedSchema {
		return a, errors.New("unsupported schema")
	}
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return a, errors.New("invalid database")
	}
	foreign, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return a, err
	}
	invalid := foreign.Next()
	err = foreign.Err()
	foreign.Close()
	if invalid || err != nil {
		return a, errors.New("orphaned source records")
	}
	var binding []byte
	if err := db.QueryRowContext(ctx, "SELECT sealed FROM storage_key_binding WHERE id=1").Scan(&binding); err != nil {
		return a, err
	}
	plain, err := openLegacy(key, binding, "database-key-binding:center:v1")
	if err != nil || string(plain) != "vastora-database-key-binding-v1" {
		clear(plain)
		return a, errors.New("key binding mismatch")
	}
	clear(plain)
	// A future business table must be reviewed, not silently omitted from a
	// seemingly successful export. Older/newer schemas are never auto-migrated.
	names, err := db.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type='table' AND (name GLOB 'meridian_*' OR name GLOB 'landing_*')`)
	if err != nil {
		return a, err
	}
	for names.Next() {
		var name string
		if err := names.Scan(&name); err != nil {
			names.Close()
			return a, err
		}
		if !slices.Contains(businessTables, name) {
			names.Close()
			return a, errors.New("unreviewed business table")
		}
	}
	err = names.Err()
	names.Close()
	if err != nil {
		return a, err
	}
	for _, name := range businessTables {
		t, err := readTable(ctx, db, name)
		if err != nil {
			return a, err
		}
		a.Tables[name] = t
		for _, row := range t.Rows {
			id := textAt(t, row, "id")
			for i, column := range t.Columns {
				if column != "secret_id" && !strings.HasSuffix(column, "_secret_id") || row[i].Kind == "null" {
					continue
				}
				secretID := row[i].Text
				aad := secretContext(name, column, id, textAt(t, row, "account_id"))
				if row[i].Kind != "text" || secretID == "" || aad == "" {
					return a, errors.New("unrecognized secret reference")
				}
				if previous, ok := a.Secrets[secretID]; ok {
					if previous.Context != aad {
						return a, errors.New("secret ownership conflict")
					}
					continue
				}
				var sealed []byte
				if err := db.QueryRowContext(ctx, "SELECT sealed FROM secrets WHERE id=?", secretID).Scan(&sealed); err != nil {
					return a, err
				}
				value, err := openLegacy(key, sealed, aad)
				if err != nil {
					return a, errors.New("secret authentication failed")
				}
				a.Secrets[secretID] = secretValue{Context: aad, Value: value}
			}
		}
	}
	return a, nil
}

func readTable(ctx context.Context, db *sql.DB, name string) (table, error) {
	if !slices.Contains(businessTables, name) {
		return table{}, errors.New("unknown table")
	}
	rows, err := db.QueryContext(ctx, `SELECT * FROM "`+name+`" ORDER BY rowid`)
	if err != nil {
		return table{}, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return table{}, err
	}
	t := table{Columns: columns, Rows: [][]cell{}}
	size := 0
	for rows.Next() {
		values, dest := make([]any, len(columns)), make([]any, len(columns))
		for i := range dest {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return t, err
		}
		row := make([]cell, len(columns))
		for i, v := range values {
			switch v := v.(type) {
			case nil:
				row[i].Kind = "null"
			case int64:
				row[i] = cell{Kind: "integer", Text: strconv.FormatInt(v, 10)}
			case string:
				row[i] = cell{Kind: "text", Text: v}
			case []byte:
				row[i] = cell{Kind: "blob", Blob: append([]byte{}, v...)}
			default:
				return t, errors.New("unsupported storage class")
			}
			size += len(row[i].Text) + len(row[i].Blob) + 32
			if size > maxSnapshotBytes {
				return t, errors.New("table too large")
			}
		}
		t.Rows = append(t.Rows, row)
	}
	return t, rows.Err()
}

func textAt(t table, row []cell, name string) string {
	i := slices.Index(t.Columns, name)
	if i < 0 || row[i].Kind != "text" {
		return ""
	}
	return row[i].Text
}

func secretContext(table, column, id, account string) string {
	switch table + "/" + column {
	case "meridian_accounts/subscription_token_secret_id":
		return "meridian-account:" + id
	case "meridian_credentials/protocol_secret_id":
		return "meridian-credential:" + id
	case "meridian_credentials/hy2_auth_secret_id":
		return "meridian-credential-hy2:" + id
	case "meridian_endpoints/private_key_secret_id":
		return "meridian-endpoint:" + id
	case "meridian_endpoints/hy2_certificate_secret_id":
		return "meridian-hy2-certificate:" + id
	case "meridian_endpoints/hy2_private_key_secret_id":
		return "meridian-hy2-private-key:" + id
	case "meridian_cutover/import_secret_id":
		return "meridian-cutover-import:v1"
	case "meridian_subscription_snapshots/secret_id":
		return "meridian-subscription-snapshot:" + account
	case "landing_client_grants/credential_secret_id":
		return "landing-credential:" + id
	case "landing_client_grants/material_secret_id":
		return "landing-material:" + id
	}
	return ""
}

func openLegacy(key, sealed []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("invalid legacy ciphertext")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(aad))
}

func writeNewPrivate(path string, raw []byte) error {
	if err := safeParent(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			os.Remove(path)
		}
	}()
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}
