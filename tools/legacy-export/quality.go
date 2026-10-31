package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/petauron/glivela/control"
	"github.com/petauron/glivela/ipquality"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Read-only SQLite transaction also supports a live WAL database. Prefer the
// existing consistent backup when one already covers this recovery scope.
func exportQuality(args []string) error {
	flags := flag.NewFlagSet("quality", flag.ContinueOnError)
	database := flags.String("database", "", "absolute source database path (read-only)")
	output := flags.String("output", "", "new private JSON file; never stdout")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !filepath.IsAbs(*database) || !filepath.IsAbs(*output) || *database == *output {
		return errors.New("invalid quality export paths")
	}
	info, err := os.Lstat(*database)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("invalid source database")
	}
	if safeParent(*output) != nil {
		return errors.New("unsafe output parent")
	}
	u := url.URL{Scheme: "file", Path: *database, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT agent_id,address,id,state,error,result_json,checked_at,updated_at FROM ip_quality_checks ORDER BY agent_id,address")
	if err != nil {
		return err
	}
	defer rows.Close()
	history := control.QualityHistory{Version: 1, Checks: []control.QualityCheck{}}
	reports := 0
	for rows.Next() {
		var c control.QualityCheck
		var raw string
		if rows.Scan(&c.NodeID, &c.Address, &c.ID, &c.State, &c.Error, &raw, &c.CheckedAt, &c.UpdatedAt) != nil {
			return errors.New("invalid source row")
		}
		if c.State == "pending" || c.State == "running" {
			c.State = "failed"
			c.Error = "interrupted"
		}
		if raw != "null" {
			var report ipquality.Report
			if json.Unmarshal([]byte(raw), &report) != nil || (ipquality.Result{Report: &report}).Validate(c.Address) != nil {
				return errors.New("invalid historical report")
			}
			c.Report = &report
			reports++
		}
		if len(history.Checks) >= 4096 {
			return errors.New("quality export limit")
		}
		history.Checks = append(history.Checks, c)
	}
	if rows.Err() != nil {
		return errors.New("source read failed")
	}
	if tx.Commit() != nil {
		return errors.New("source transaction failed")
	}
	// Import performs complete identity/timestamp validation again. Export never
	// assigns certificates, leases or authority to execute a diagnostic.
	b, err := json.Marshal(struct {
		Import control.QualityHistory `json:"import"`
	}{history})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			os.Remove(*output)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	complete = true
	fmt.Printf("Exported %d rows and %d reports; source unchanged.\n", len(history.Checks), reports)
	return nil
}
