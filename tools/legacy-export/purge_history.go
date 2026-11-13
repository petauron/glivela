package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

// This is an explicitly authorized offline maintenance operation, not a
// runtime compatibility path or a way to restore the old business writer.
type historyRedaction struct {
	ids   map[string]bool
	words []string
}

func (r historyRedaction) owned(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"id", "nodeId", "node_id", "agentId", "agent_id", "entryId", "entry_id", "egressId", "egress_id", "egressNodeId", "egress_node_id", "ipv4EgressId", "ipv4_egress_node_id", "landingId", "landingNodeId", "landing_node_id", "applicationId", "application_id", "credentialId", "credential_id", "routeId", "route_id", "taskId", "task_id", "executionId", "execution_id", "tag", "outboundTag"} {
		if s, ok := m[k].(string); ok && r.ids[s] {
			return true
		}
	}
	for _, k := range []string{"grant", "credential"} {
		if x, ok := m[k]; ok && r.owned(x) {
			return true
		}
	}
	return false
}
func (r historyRedaction) value(v any, depth int) any {
	if depth > 32 {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		if r.owned(x) {
			return nil
		}
		m := make(map[string]any, len(x))
		for k, v := range x {
			if r.ids[k] {
				continue
			}
			z := r.value(v, depth+1)
			if z != nil || v == nil {
				m[k] = z
			}
		}
		return m
	case []any:
		a := make([]any, 0, len(x))
		for _, v := range x {
			if s, ok := v.(string); ok && r.ids[s] {
				continue
			}
			z := r.value(v, depth+1)
			if z != nil || v == nil {
				a = append(a, z)
			}
		}
		return a
	case string:
		return r.text(x, depth+1)
	default:
		return v
	}
}
func (r historyRedaction) text(s string, depth int) string {
	if depth < 32 {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if len(s) < 16 {
				break
			}
			decoded, err := encoding.Strict().DecodeString(s)
			if err != nil || !utf8.Valid(decoded) {
				continue
			}
			next, err := r.payload(decoded, depth+1)
			if err == nil && !bytes.Equal(next, decoded) {
				return encoding.EncodeToString(next)
			}
		}
		if json.Valid([]byte(s)) && strings.TrimSpace(s) != "" && (strings.HasPrefix(strings.TrimSpace(s), "{") || strings.HasPrefix(strings.TrimSpace(s), "[")) {
			if next, err := r.payload([]byte(s), depth+1); err == nil && !bytes.Equal(next, []byte(s)) {
				return string(next)
			}
		}
	}
	for _, word := range r.words {
		s = strings.ReplaceAll(s, word, "[retired]")
	}
	return s
}
func (r historyRedaction) payload(raw []byte, depth int) ([]byte, error) {
	if !utf8.Valid(raw) {
		return raw, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return []byte(r.text(string(raw), 32)), nil
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return []byte(r.text(string(raw), 32)), nil
	}
	next := r.value(v, depth+1)
	if reflect.DeepEqual(v, next) {
		return raw, nil
	}
	return json.Marshal(next)
}
func legacySeal(key, plain []byte, aad string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, plain, []byte(aad)), nil
}
func collectHistoricalSecrets(raw []byte) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var words []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				key := strings.ToLower(strings.ReplaceAll(k, "_", ""))
				if s, ok := v.(string); ok && len(s) >= 8 && (key == "key" || key == "serverkey" || key == "transportkey" || key == "privatekey" || key == "privatekeypem" || strings.HasSuffix(key, "password") || key == "secret" || key == "secretvalue" || strings.HasSuffix(key, "credential") || strings.HasSuffix(key, "authkey") || key == "auth" || key == "hy2auth" || key == "token" || key == "protocolid") {
					if json.Valid([]byte(s)) {
						walkJSON := collectHistoricalSecrets([]byte(s))
						words = append(words, walkJSON...)
					} else {
						words = append(words, s)
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		case string:
			if len(x) > 32 {
				if decoded, e := base64.StdEncoding.Strict().DecodeString(x); e == nil && json.Valid(decoded) {
					words = append(words, collectHistoricalSecrets(decoded)...)
				}
			}
		}
	}
	walk(v)
	return words
}

func purgeArchiveHistory(a archive, ids map[string]bool, sourceKey []byte, protected map[string]bool) (archive, historyRedaction, error) {
	r := historyRedaction{ids: map[string]bool{}}
	for id := range ids {
		r.ids[id] = true
	}
	for id, n := range a.References.Nodes {
		if ids[id] && len(n.Name) > 3 {
			r.words = append(r.words, n.Name)
		}
	}
	for id, v := range a.References.Applications {
		if ids[v.NodeID] {
			r.ids[id] = true
		}
	}
	for id, v := range a.References.Services {
		if r.ids[v.ApplicationID] {
			r.ids[id] = true
		}
	}
	for id, v := range a.References.Publications {
		if ids[v.EntryNodeID] || r.ids[v.ServiceID] {
			r.ids[id] = true
		}
	}
	for _, name := range []string{"meridian_credentials", "meridian_route_grants"} {
		t := a.Tables[name]
		for _, row := range t.Rows {
			if ids[textAt(t, row, "egress_node_id")] || ids[textAt(t, row, "ipv4_egress_node_id")] || r.ids[textAt(t, row, "endpoint_id")] {
				id := textAt(t, row, "id")
				if id != "" {
					r.ids[id] = true
					if name == "meridian_route_grants" {
						sum := sha256.Sum256([]byte(id))
						r.ids["meridian-route-"+hex.EncodeToString(sum[:])[:32]] = true
					}
				}
			}
		}
	}
	ownerColumns := []string{"id", "node_id", "agent_id", "entry_node_id", "egress_node_id", "ipv4_egress_node_id", "landing_node_id", "application_id", "service_id", "credential_id", "route_id", "task_id", "execution_id", "command_id"}
	removeRow := func(t table, row []cell) bool {
		for _, c := range ownerColumns {
			if r.ids[textAt(t, row, c)] {
				return true
			}
		}
		return false
	}
	candidates := map[string]bool{}
	for pass := 0; pass < 4; pass++ {
		for name, t := range a.Tables {
			out := make([][]cell, 0, len(t.Rows))
			for _, row := range t.Rows {
				if !removeRow(t, row) {
					out = append(out, row)
					continue
				}
				for _, c := range row {
					if c.Kind == "blob" && json.Valid(c.Blob) {
						r.words = append(r.words, collectHistoricalSecrets(c.Blob)...)
					} else if c.Kind == "text" && json.Valid([]byte(c.Text)) {
						r.words = append(r.words, collectHistoricalSecrets([]byte(c.Text))...)
					}
				}
				if slices.Contains(historyTables, name) {
					if id := textAt(t, row, "id"); id != "" {
						r.ids[id] = true
					}
				}
				for i, col := range t.Columns {
					if col == "secret_id" || strings.HasSuffix(col, "_secret_id") {
						if row[i].Kind == "text" {
							candidates[row[i].Text] = true
						}
					}
				}
			}
			t.Rows = out
			a.Tables[name] = t
		}
	}
	referenced := map[string]bool{}
	for _, t := range a.Tables {
		for _, row := range t.Rows {
			for i, c := range t.Columns {
				if c == "secret_id" || strings.HasSuffix(c, "_secret_id") {
					if row[i].Kind == "text" {
						referenced[row[i].Text] = true
					}
				}
			}
		}
	}
	// A secret still referenced by another owner is not a deletion candidate.
	for id := range candidates {
		if referenced[id] {
			continue
		}
		if v, ok := a.Secrets[id]; ok {
			r.words = append(r.words, collectHistoricalSecrets(v.Value)...)
			if utf8.Valid(v.Value) && len(v.Value) >= 8 && !json.Valid(v.Value) {
				r.words = append(r.words, string(v.Value))
			}
			delete(a.Secrets, id)
		}
	}
	for context, v := range a.HistoryPayloads {
		parts := strings.SplitN(context, ":", 2)
		if len(parts) == 2 && r.ids[parts[1]] {
			r.words = append(r.words, collectHistoricalSecrets(v.Value)...)
		}
	}
	for id := range r.ids {
		r.words = append(r.words, id)
	}
	for _, word := range slices.Clone(r.words) {
		if len(word) == 36 && strings.Count(word, "-") == 4 {
			r.words = append(r.words, strings.ToUpper(word), strings.ToLower(word))
		}
	}
	r.words = slices.DeleteFunc(r.words, func(word string) bool { return word == "" || protected[word] })
	slices.SortFunc(r.words, func(a, b string) int { return len(b) - len(a) })
	r.words = slices.Compact(r.words)
	for key, v := range a.HistoryPayloads {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 2 && r.ids[parts[1]] {
			delete(a.HistoryPayloads, key)
			continue
		}
		next, err := r.payload(v.Value, 0)
		if err != nil {
			return a, r, err
		}
		v.Value = next
		a.HistoryPayloads[key] = v
	}
	for id, v := range a.Secrets {
		next, err := r.payload(v.Value, 0)
		if err != nil {
			return a, r, err
		}
		v.Value = next
		a.Secrets[id] = v
	}
	for name, t := range a.Tables {
		for i, row := range t.Rows {
			for j, c := range row {
				if name == "task_executions" && c.Kind == "blob" && (t.Columns[j] == "sealed_task" || t.Columns[j] == "sealed_result") {
					if len(c.Blob) == 0 {
						continue
					}
					prefix := "execution-task:"
					if t.Columns[j] == "sealed_result" {
						prefix = "execution-result:"
					}
					aad := prefix + textAt(t, row, "id")
					plain, err := openLegacy(sourceKey, c.Blob, aad)
					if err != nil {
						return a, r, errors.New("historical execution authentication failed")
					}
					next, err := r.payload(plain, 0)
					if err != nil {
						return a, r, err
					}
					if !bytes.Equal(next, plain) {
						c.Blob, err = legacySeal(sourceKey, next, aad)
						if err != nil {
							return a, r, err
						}
					}
					clear(plain)
				} else if c.Kind == "blob" && json.Valid(c.Blob) {
					next, err := r.payload(c.Blob, 0)
					if err != nil {
						return a, r, err
					}
					c.Blob = next
				} else if c.Kind == "text" {
					c.Text = r.text(c.Text, 0)
				}
				row[j] = c
			}
			t.Rows[i] = row
		}
		a.Tables[name] = t
	}
	// Snapshot checksums describe the redacted payload, not its former bytes.
	if t, ok := a.Tables["meridian_subscription_snapshots"]; ok {
		for i, row := range t.Rows {
			v := a.Secrets[textAt(t, row, "secret_id")]
			sum := sha256.Sum256(v.Value)
			j := slices.Index(t.Columns, "content_sha256")
			if j < 0 {
				return a, r, errors.New("snapshot checksum column missing")
			}
			row[j] = cell{Kind: "text", Text: hex.EncodeToString(sum[:])}
			t.Rows[i] = row
		}
		a.Tables["meridian_subscription_snapshots"] = t
	}
	raw, err := json.Marshal(a.References)
	if err != nil {
		return a, r, err
	}
	raw, err = r.payload(raw, 0)
	var references glivela.ImportReferences
	if err != nil || json.Unmarshal(raw, &references) != nil {
		return a, r, errors.New("redacted references invalid")
	}
	a.References = references
	a.HistoryRedacted = true
	return a, r, nil
}
func redactCenterHistory(ctx context.Context, directory string, r historyRedaction) (int, error) {
	key, err := privateFile(filepath.Join(directory, "center.key"), 32)
	if err != nil {
		return 0, err
	}
	defer clear(key)
	path := filepath.Join(directory, "center.db")
	if err := standalone(path); err != nil {
		return 0, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=foreign_keys(1)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, `PRAGMA secure_delete=ON`); err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var retired bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM retired_proxy_business WHERE id=1)`).Scan(&retired); err != nil || !retired {
		return 0, errors.New("historical Center writer is not retired")
	}
	type item struct {
		id, aad string
		sealed  []byte
	}
	items := map[string]item{}
	for _, q := range []string{
		`SELECT s.id,'meridian-subscription-snapshot:'||p.account_id,s.sealed FROM meridian_subscription_snapshots p JOIN secrets s ON s.id=p.secret_id`,
		`SELECT s.id,'meridian-cutover-import:v1',s.sealed FROM meridian_cutover p JOIN secrets s ON s.id=p.import_secret_id`,
		`SELECT s.id,'deployment:'||p.id,s.sealed FROM deployments p JOIN secrets s ON s.id=p.secret_id`,
		`SELECT s.id,'application-command:'||p.id,s.sealed FROM application_commands p JOIN secrets s ON s.id=p.result_secret_id`,
		`SELECT s.id,'application:'||p.application_id,s.sealed FROM application_secrets p JOIN secrets s ON s.id=p.secret_id`,
	} {
		rows, e := tx.QueryContext(ctx, q)
		if e != nil {
			return 0, e
		}
		for rows.Next() {
			var v item
			if e = rows.Scan(&v.id, &v.aad, &v.sealed); e != nil {
				rows.Close()
				return 0, e
			}
			if old, ok := items[v.id]; ok && old.aad != v.aad {
				rows.Close()
				return 0, errors.New("historical secret owner differs")
			}
			items[v.id] = v
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return 0, e
		}
	}
	changed := 0
	for _, v := range items {
		plain, e := openLegacy(key, v.sealed, v.aad)
		if e != nil {
			return changed, errors.New("Center historical secret authentication failed")
		}
		next, e := r.payload(plain, 0)
		if e != nil {
			return changed, e
		}
		if bytes.Equal(next, plain) {
			clear(plain)
			continue
		}
		clear(plain)
		sealed, e := legacySeal(key, next, v.aad)
		if e != nil {
			return changed, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE secrets SET sealed=? WHERE id=?`, sealed, v.id); e != nil {
			return changed, e
		}
		if strings.HasPrefix(v.aad, "meridian-subscription-snapshot:") {
			var original string
			if e = tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE name='retired_proxy_meridian_subscription_snapshots_update'`).Scan(&original); e != nil {
				return changed, e
			}
			prefix := "CREATE TRIGGER retired_proxy_meridian_subscription_snapshots_update BEFORE UPDATE ON meridian_subscription_snapshots WHEN EXISTS(SELECT 1 FROM retired_proxy_business WHERE id=1)"
			suffix := " BEGIN SELECT RAISE(ABORT,'proxy business permanently handed over to Glivela'); END"
			if strings.TrimSuffix(original, ";") != prefix+suffix {
				return changed, errors.New("snapshot guard differs")
			}
			if _, e = tx.ExecContext(ctx, `DROP TRIGGER retired_proxy_meridian_subscription_snapshots_update`); e != nil {
				return changed, e
			}
			guard := prefix + " AND OLD.secret_id<>'" + strings.ReplaceAll(v.id, "'", "''") + "'" + suffix
			if _, e = tx.ExecContext(ctx, guard); e != nil {
				return changed, e
			}
			sum := sha256.Sum256(next)
			if _, e = tx.ExecContext(ctx, `UPDATE meridian_subscription_snapshots SET content_sha256=? WHERE secret_id=?`, hex.EncodeToString(sum[:]), v.id); e != nil {
				return changed, e
			}
			if _, e = tx.ExecContext(ctx, `DROP TRIGGER retired_proxy_meridian_subscription_snapshots_update`); e != nil {
				return changed, e
			}
			if _, e = tx.ExecContext(ctx, original); e != nil {
				return changed, e
			}
		}
		changed++
	}
	// Execution evidence can carry historical proxy secrets outside secrets.
	rows, err := tx.QueryContext(ctx, `SELECT id,sealed_task,sealed_result FROM task_executions`)
	if err != nil {
		return changed, err
	}
	type execution struct {
		id           string
		task, result []byte
	}
	var executions []execution
	for rows.Next() {
		var v execution
		if err = rows.Scan(&v.id, &v.task, &v.result); err != nil {
			rows.Close()
			return changed, err
		}
		executions = append(executions, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return changed, err
	}
	for _, v := range executions {
		for _, part := range []struct {
			column, aad string
			sealed      []byte
		}{{"sealed_task", "execution-task:", v.task}, {"sealed_result", "execution-result:", v.result}} {
			if len(part.sealed) == 0 {
				continue
			}
			plain, e := openLegacy(key, part.sealed, part.aad+v.id)
			if e != nil {
				return changed, errors.New("Center execution authentication failed")
			}
			next, e := r.payload(plain, 0)
			if e != nil {
				return changed, e
			}
			if !bytes.Equal(next, plain) {
				sealed, e := legacySeal(key, next, part.aad+v.id)
				if e != nil {
					return changed, e
				}
				if _, e = tx.ExecContext(ctx, "UPDATE task_executions SET "+part.column+"=? WHERE id=?", sealed, v.id); e != nil {
					return changed, e
				}
				changed++
			}
			clear(plain)
		}
	}
	plainChanged, err := redactPlainCenterHistory(ctx, tx, r)
	if err != nil {
		return changed, err
	}
	changed += plainChanged
	rows, err = tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return changed, err
	}
	broken := rows.Next()
	rows.Close()
	if broken {
		return changed, errors.New("Center history references invalid")
	}
	if err := tx.Commit(); err != nil {
		return changed, err
	}
	_, err = db.ExecContext(ctx, `VACUUM`)
	return changed, err
}
func redactPlainCenterHistory(ctx context.Context, tx *sql.Tx, r historyRedaction) (int, error) {
	changed := 0
	for _, name := range []string{"execution_events", "task_events", "task_executions", "node_diagnostic_checks", "ip_quality_checks", "application_commands", "deployments"} {
		rows, e := tx.QueryContext(ctx, "SELECT rowid,* FROM "+name)
		if e != nil {
			return changed, e
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			return changed, e
		}
		var records [][]any
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(values))
			for i := range values {
				pointers[i] = &values[i]
			}
			if e = rows.Scan(pointers...); e != nil {
				rows.Close()
				return changed, e
			}
			records = append(records, values)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return changed, e
		}
		for _, record := range records {
			owner := map[string]any{}
			for i, c := range columns {
				if v, ok := record[i].(string); ok {
					owner[c] = v
				}
			}
			pair, _ := owner["pair_key"].(string)
			if r.owned(owner) || r.text(pair, 0) != pair {
				if state, ok := owner["state"].(string); ok && (state == "pending" || state == "running") {
					return changed, errors.New("active history owner requires completion before redaction")
				}
				if _, e = tx.ExecContext(ctx, "DELETE FROM "+name+" WHERE rowid=?", record[0]); e != nil {
					return changed, e
				}
				changed++
				continue
			}
			for i, c := range columns {
				if i == 0 || c == "sealed_task" || c == "sealed_result" {
					continue
				}
				var before, after []byte
				switch v := record[i].(type) {
				case string:
					before = []byte(v)
					after = []byte(r.text(v, 0))
				case []byte:
					if !json.Valid(v) {
						continue
					}
					before = v
					after, e = r.payload(v, 0)
					if e != nil {
						return changed, e
					}
				default:
					continue
				}
				if bytes.Equal(before, after) {
					continue
				}
				if state, ok := owner["state"].(string); ok && (state == "pending" || state == "running") {
					return changed, errors.New("active history owner requires completion before redaction")
				}
				var value any = after
				if _, ok := record[i].(string); ok {
					value = string(after)
				}
				if _, e = tx.ExecContext(ctx, "UPDATE "+name+" SET \""+c+"\"=? WHERE rowid=?", value, record[0]); e != nil {
					return changed, e
				}
				changed++
			}
		}
	}
	return changed, nil
}

// Root performs offline maintenance, while the live application may use a
// restricted service UID. Atomic replacement must retain its established owner.
func preserveHistoryOwner(file *os.File, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private history owner unavailable")
	}
	return file.Chown(int(stat.Uid), int(stat.Gid))
}

func purgeHistoryCommand(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("purge-retired-history", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	directory := f.String("state-directory", "", "stopped controller state")
	center := f.String("center-directory", "", "stopped Center state")
	nodes := f.String("node-ids", "", "comma-separated exact retired identities")
	confirmed := f.Bool("confirm-stopped-writers", false, "both writers are stopped; permanently remove target historical secrets")
	audit := f.String("audit-file", "", "new private file for nonrecoverable token fingerprints")
	historyFiles := f.String("history-file-list", "", "private JSON list of explicit inactive history JSON files")
	if f.Parse(args) != nil || f.NArg() != 0 || os.Geteuid() != 0 || !*confirmed || *directory == "" || *center == "" {
		return errors.New("confirmed offline root history purge required")
	}
	unlock, err := control.LockDirectory(*directory)
	if err != nil {
		return err
	}
	defer unlock()
	ids := map[string]bool{}
	for _, id := range strings.Split(*nodes, ",") {
		if !glivela.ValidIdentifier(id) || ids[id] {
			return errors.New("exact retired identities required")
		}
		ids[id] = true
	}
	path := filepath.Join(*directory, "business.json")
	before, err := privateFile(path, 90<<20)
	if err != nil {
		return err
	}
	var checkpoint struct {
		Version    int    `json:"version"`
		SnapshotID string `json:"snapshotId"`
		Sealed     []byte `json:"sealed"`
	}
	if json.Unmarshal(before, &checkpoint) != nil || checkpoint.Version != 1 {
		return errors.New("owned checkpoint invalid")
	}
	key, err := privateFile(filepath.Join(*directory, "business.key"), 32)
	if err != nil {
		return err
	}
	defer clear(key)
	m, err := glivela.OpenImportMaterial(checkpoint.Sealed, key, checkpoint.SnapshotID)
	if err != nil || m.Ownership == nil {
		return errors.New("owned checkpoint authentication failed")
	}
	for id := range ids {
		if _, ok := m.RetiredLandings[id]; !ok {
			return errors.New("landing retirement must complete first")
		}
	}
	sourceKey, err := privateFile(filepath.Join(*center, "center.key"), 32)
	if err != nil {
		return err
	}
	defer clear(sourceKey)
	var a archive
	if json.Unmarshal(m.RetainedSource, &a) != nil || a.SourceSHA256 != m.SourceSHA256 || a.SnapshotID != checkpoint.SnapshotID {
		return errors.New("retained source identity differs")
	}
	protected := map[string]bool{}
	for _, values := range []map[string]string{m.ProtocolSecrets, m.HysteriaSecrets, m.SubscriptionTokens} {
		for _, value := range values {
			protected[value] = true
			if len(value) == 36 && strings.Count(value, "-") == 4 {
				protected[strings.ToUpper(value)] = true
				protected[strings.ToLower(value)] = true
			}
		}
	}
	for _, landing := range m.ClientLandings {
		protected[landing.Key] = true
	}
	for _, endpoint := range m.Endpoints {
		protected[endpoint.Reality.PrivateKey] = true
		if endpoint.Hysteria != nil {
			protected[endpoint.Hysteria.PrivateKeyPEM] = true
		}
	}
	a, r, err := purgeArchiveHistory(a, ids, sourceKey, protected)
	if err != nil {
		return err
	}
	if *audit != "" {
		fingerprints := make([]string, 0, len(r.words))
		for _, word := range r.words {
			sum := sha256.Sum256([]byte(word))
			fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
		}
		slices.Sort(fingerprints)
		fingerprints = slices.Compact(fingerprints)
		raw, e := json.Marshal(struct {
			Version      int      `json:"version"`
			Fingerprints []string `json:"fingerprints"`
		}{1, fingerprints})
		if e != nil {
			return e
		}
		if old, e := privateFile(*audit, 1<<20); e == nil {
			if !bytes.Equal(old, raw) {
				return errors.New("existing redaction audit differs")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if e = writeNewPrivate(*audit, raw); e != nil {
			return e
		}
	}
	m.RetainedSource, err = json.Marshal(a)
	if err != nil {
		return err
	}
	checkpoint.Sealed, err = glivela.SealImportMaterial(m, key, checkpoint.SnapshotID)
	if err != nil {
		return err
	}
	if *historyFiles != "" {
		raw, e := privateFile(*historyFiles, 1<<20)
		if e != nil {
			return e
		}
		var paths []string
		if json.Unmarshal(raw, &paths) != nil {
			return errors.New("history file list invalid")
		}
		for _, path := range paths {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasSuffix(path, ".json") || path == filepath.Join(*directory, "business.json") {
				return errors.New("history file scope invalid")
			}
			before, e := privateFile(path, 90<<20)
			if e != nil {
				return e
			}
			if !json.Valid(before) {
				return errors.New("history JSON invalid")
			}
			after, e := r.payload(before, 0)
			if e != nil {
				return e
			}
			if bytes.Equal(before, after) {
				continue
			}
			tmp, e := os.CreateTemp(filepath.Dir(path), ".redacted-history-")
			if e != nil {
				return e
			}
			name := tmp.Name()
			if e = tmp.Chmod(0600); e == nil {
				e = preserveHistoryOwner(tmp, path)
			}
			if e == nil {
				_, e = tmp.Write(after)
			}
			if e == nil {
				e = tmp.Sync()
			}
			closeErr := tmp.Close()
			if e == nil {
				e = closeErr
			}
			if e == nil {
				e = os.Rename(name, path)
			}
			_ = os.Remove(name)
			if e != nil {
				return e
			}
		}
	}
	// Complete Center first: an interrupted retry can still derive the exact
	// scope from the not-yet-replaced controller archive, without a new backup.
	changed, err := redactCenterHistory(ctx, *center, r)
	if err != nil {
		return err
	}
	after, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	observed, err := privateFile(path, 90<<20)
	if err != nil || !bytes.Equal(before, observed) {
		return errors.New("controller writer changed during history purge")
	}
	tmp, err := os.CreateTemp(*directory, ".history-purge-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		err = preserveHistoryOwner(tmp, path)
	}
	if err == nil {
		_, err = tmp.Write(after)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(*directory)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return err
	}
	fmt.Printf("Historical archive redacted; Center encrypted payloads changed: %d; current node policy and account ledger unchanged.\n", changed)
	return nil
}
