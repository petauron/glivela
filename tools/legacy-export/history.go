package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
)

var historyTables = []string{"application_commands", "deployments", "node_diagnostic_checks", "ip_quality_checks", "task_events", "task_executions", "execution_events"}

// Archive only the proxy's referenced applications/nodes and their linked
// history. This is evidence, never a queue, desired config, execution authority
// or a reason to restore old leases. Raw integer/blob cells remain unchanged.
func readSelectedHistory(ctx context.Context, db *sql.DB, key []byte, a *archive) error {
	applications := slices.Sorted(maps.Keys(a.References.Applications))
	nodes := slices.Sorted(maps.Keys(a.References.Nodes))
	appJSON, err := json.Marshal(applications)
	if err != nil {
		return err
	}
	nodeJSON, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	read := func(name, query string, args ...any) error {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err // A schema-113 database missing these tables is incomplete.
		}
		t, err := decodeTableRows(rows)
		if err != nil {
			return err
		}
		a.Tables[name] = t
		return nil
	}
	if err := read("application_commands", `SELECT * FROM application_commands WHERE application_id IN (SELECT value FROM json_each(?)) AND (kind GLOB 'meridian.*' OR kind GLOB '3xui.*') ORDER BY rowid`, string(appJSON)); err != nil {
		return err
	}
	if err := read("deployments", `SELECT * FROM deployments WHERE application_id IN (SELECT value FROM json_each(?)) ORDER BY rowid`, string(appJSON)); err != nil {
		return err
	}
	if err := read("node_diagnostic_checks", `SELECT * FROM node_diagnostic_checks WHERE agent_id IN (SELECT value FROM json_each(?)) AND kind IN ('node.network-quality','node.return-route','node.international-bandwidth','meridian.link-bandwidth','meridian.link-bandwidth-server') ORDER BY rowid`, string(nodeJSON)); err != nil {
		return err
	}
	if err := read("ip_quality_checks", `SELECT * FROM ip_quality_checks WHERE agent_id IN (SELECT value FROM json_each(?)) ORDER BY rowid`, string(nodeJSON)); err != nil {
		return err
	}
	tasks := map[string]bool{}
	for _, name := range []string{"application_commands", "deployments", "node_diagnostic_checks", "ip_quality_checks", "meridian_deployments"} {
		t := a.Tables[name]
		for _, row := range t.Rows {
			if id := textAt(t, row, "id"); id != "" {
				tasks[id] = true
			}
			for _, column := range t.Columns {
				if column == "command_id" || strings.HasSuffix(column, "_task_id") {
					if id := textAt(t, row, column); id != "" {
						tasks[id] = true
					}
				}
			}
		}
	}
	taskJSON, err := json.Marshal(slices.Sorted(maps.Keys(tasks)))
	if err != nil {
		return err
	}
	for _, name := range []string{"task_events", "task_executions"} {
		// Table names are fixed above, never values from the source snapshot.
		query := `SELECT * FROM "` + name + `" WHERE task_id IN (SELECT value FROM json_each(?)) OR (agent_id IN (SELECT value FROM json_each(?)) AND kind GLOB 'meridian.*') ORDER BY rowid`
		if err := read(name, query, string(taskJSON), string(nodeJSON)); err != nil {
			return err
		}
	}
	executions := a.Tables["task_executions"]
	ids := make([]string, 0, len(executions.Rows))
	for _, row := range executions.Rows {
		ids = append(ids, textAt(executions, row, "id"))
	}
	executionJSON, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	if err := read("execution_events", `SELECT * FROM execution_events WHERE execution_id IN (SELECT value FROM json_each(?)) ORDER BY rowid`, string(executionJSON)); err != nil {
		return err
	}
	return readHistoryPayloads(ctx, db, key, a)
}

func readHistoryPayloads(ctx context.Context, db *sql.DB, key []byte, a *archive) error {
	a.HistoryPayloads = map[string]secretValue{}
	retain := func(context string, sealed []byte) error {
		if len(sealed) == 0 {
			return nil
		}
		plain, err := openLegacy(key, sealed, context)
		if err != nil {
			return errors.New("historical payload authentication failed")
		}
		a.HistoryPayloads[context] = secretValue{Context: context, Value: plain}
		return nil
	}
	for _, spec := range []struct{ table, column, prefix string }{
		{"application_commands", "result_secret_id", "application-command:"},
		{"deployments", "secret_id", "deployment:"},
	} {
		t := a.Tables[spec.table]
		for _, row := range t.Rows {
			id := textAt(t, row, spec.column)
			if id == "" {
				continue
			}
			var sealed []byte
			if err := db.QueryRowContext(ctx, `SELECT sealed FROM secrets WHERE id=?`, id).Scan(&sealed); err != nil {
				return err
			}
			if err := retain(spec.prefix+textAt(t, row, "id"), sealed); err != nil {
				return err
			}
		}
	}
	t := a.Tables["task_executions"]
	for _, row := range t.Rows {
		for _, field := range []struct{ column, prefix string }{{"sealed_task", "execution-task:"}, {"sealed_result", "execution-result:"}} {
			index := slices.Index(t.Columns, field.column)
			if index < 0 || row[index].Kind != "blob" {
				return errors.New("historical execution payload column missing")
			}
			if err := retain(field.prefix+textAt(t, row, "id"), row[index].Blob); err != nil {
				return err
			}
		}
	}
	return nil
}
