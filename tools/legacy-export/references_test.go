package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/petauron/glivela/control"
)

func referenceFixture(t *testing.T) (*sql.DB, archive) {
	t.Helper()
	_, _, db := fixture(t)
	db.SetMaxOpenConns(1)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE TABLE agents(id TEXT PRIMARY KEY,name TEXT,status TEXT,landing_egress_addresses_json TEXT,credential_hash BLOB)")
	exec("CREATE TABLE agent_network_profiles(agent_id TEXT PRIMARY KEY,service_address TEXT,headscale_address TEXT)")
	exec("CREATE TABLE agent_private_peer_capabilities(node_id TEXT PRIMARY KEY,peer_json BLOB)")
	exec("CREATE TABLE services(id TEXT PRIMARY KEY,application_id TEXT,name TEXT,display_name TEXT,region_code TEXT,protocol TEXT,app_protocol TEXT,container_port INTEGER,host_port INTEGER,endpoint TEXT,status TEXT)")
	exec("CREATE TABLE publications(id TEXT PRIMARY KEY,service_id TEXT,entry_node_id TEXT,kind TEXT,ingress_owner TEXT,hostname TEXT,sni_hostname TEXT,dns_provider TEXT,dns_record_id TEXT,access_application_id TEXT,tls_enabled INTEGER,desired_revision INTEGER,applied_revision INTEGER,status TEXT,last_error TEXT,action_required INTEGER,cleanup_pending INTEGER,cleanup_attempt INTEGER,cleanup_retry_at TEXT,created_at TEXT,updated_at TEXT)")
	for _, n := range []struct{ id, name, status string }{{"entry-host-example", "Entry host", "active"}, {"landing-example", "Landing host", "disabled"}, {"candidate-node", "Candidate", "disabled"}, {"unrelated-node", "do-not-export-node-name", "active"}} {
		exec("INSERT INTO agents VALUES(?,?,?,'[]',?)", n.id, n.name, n.status, []byte("do-not-export-agent-hash"))
	}
	exec("INSERT INTO applications VALUES('entry-example','Existing proxy','entry-host-example','docker','running','vastora-official/meridian')")
	exec("INSERT INTO applications VALUES('candidate-app','Unconfigured proxy','candidate-node','host','pending','vastora-official/meridian')")
	exec("INSERT INTO applications VALUES('unrelated-app','do-not-export-app-name','unrelated-node','docker','running','example/unrelated')")
	exec("INSERT INTO agent_network_profiles VALUES('entry-host-example','100.64.0.2','100.64.0.2')")
	exec("INSERT INTO agent_private_peer_capabilities VALUES('entry-host-example',?)", []byte(`{"id":"peer-example","address":"100.64.0.2"}`))
	exec("INSERT INTO services VALUES('service-example','entry-example','entry','Saved entry','US','tcp','meridian/entry',10443,443,'100.64.0.2:10443','ready')")
	exec("INSERT INTO services VALUES('unrelated-service','unrelated-app','subscription','do-not-export-service-name','','http','',8080,8080,'127.0.0.1:8080','ready')")
	exec("CREATE TABLE sites(id TEXT PRIMARY KEY,timezone TEXT NOT NULL)")
	exec("INSERT INTO sites VALUES('site-example','Asia/Shanghai')")
	exec("ALTER TABLE services ADD COLUMN site_id TEXT NOT NULL DEFAULT 'site-example'")
	exec(`INSERT INTO publications VALUES('publication-example','service-example','entry-host-example','public_shared_443','application_node','entry.example.test','www.example.com','cloudflare','dns-record-example','access-example',1,7,6,'failed','synthetic error',1,1,2,'2026-10-20T00:00:00Z','2026-09-19T00:00:00Z','2026-10-19T02:03:04Z')`)
	exec(`INSERT INTO publications VALUES('unrelated-publication','unrelated-service','unrelated-node','public_direct','application_node','unrelated.example.test','','manual','','',0,1,1,'ready','',0,0,0,'','2026-09-19T00:00:00Z','2026-10-19T02:03:04Z')`)
	exec(`INSERT INTO settings VALUES('meridian_landing_selection','{"nodeIds":["landing-example"],"landingRegionCodes":{"landing-example":"TW"},"landingNameSuffixes":{"landing-example":"Saved"},"revision":9}')`)
	exec("INSERT INTO settings VALUES('cloudflare_token','do-not-export-provider-token')")
	return db, completeEndpointArchiveFixture(t)
}

func TestRealLegacyReferenceBindings(t *testing.T) {
	a, ok := realLegacyAccountArchive(t)
	if !ok {
		return
	}
	dir := os.Getenv("GLIVELA_ACCOUNT_FIXTURE_DIR")
	u := url.URL{Scheme: "file", Path: filepath.Join(dir, "center.db"), RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal("fixture source unavailable")
	}
	defer db.Close()
	var nodeID, appName, displayName, region, publicationID, hostname, nodeName string
	if err := db.QueryRow(`SELECT a.node_id,a.name,s.display_name,s.region_code,p.id,p.hostname,n.name FROM meridian_endpoints e JOIN applications a ON a.id=e.application_id JOIN agents n ON n.id=a.node_id JOIN services s ON s.id=e.service_id JOIN publications p ON p.service_id=s.id WHERE e.id='snapshot-shared-endpoint'`).Scan(&nodeID, &appName, &displayName, &region, &publicationID, &hostname, &nodeName); err != nil {
		t.Fatal("fixture reference query failed")
	}
	key, err := privateFile(filepath.Join(dir, "storage.key"), 32)
	if err != nil {
		t.Fatal("fixture storage key unavailable")
	}
	defer clear(key)
	m, id, err := control.ReadStagedImport(filepath.Join(dir, "controller"), key)
	if err != nil || id != a.SnapshotID {
		t.Fatal("fixture checkpoint unavailable")
	}
	r := m.References
	if r.Applications["snapshot-shared-app"].NodeID != nodeID || r.Applications["snapshot-shared-app"].Name != appName || r.Nodes[nodeID].Name != nodeName || r.Services["snapshot-shared-service"].DisplayName != displayName || r.Services["snapshot-shared-service"].RegionCode != region || r.Publications[publicationID].Hostname != hostname {
		t.Fatal("original node/service/publication binding changed")
	}
}

func TestReferenceExportPreservesOriginalGraphAndExcludesPlatformCredentials(t *testing.T) {
	db, a := referenceFixture(t)
	r, err := readReferences(context.Background(), db, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 3 || len(r.Applications) != 2 || len(r.Services) != 1 || len(r.Publications) != 1 || r.Applications["entry-example"].NodeID != "entry-host-example" || r.Nodes["landing-example"].PreviousStatus != "disabled" || r.Nodes["entry-host-example"].PrivateAddress != "100.64.0.2" {
		t.Fatal("node/application graph changed")
	}
	if r.Services["service-example"].Timezone != "Asia/Shanghai" {
		t.Fatal("source reset timezone was not retained")
	}
	if r.Services["service-example"].DisplayName != "Saved entry" || r.Publications["publication-example"].DNSRecordID != "dns-record-example" || !r.Publications["publication-example"].CleanupPending || r.Publications["publication-example"].AppliedRevision != 6 || r.LandingSelection.Revision != 9 || r.LandingSelection.LandingNameSuffixes["landing-example"] != "Saved" {
		t.Fatal("service/publication/selection configuration changed")
	}
	raw, err := json.Marshal(r)
	if err != nil || bytes.Contains(raw, []byte("do-not-export")) || bytes.Contains(raw, []byte("unrelated-app")) {
		t.Fatal("unrelated platform information exported")
	}
	a.References = r
	m, err := importMaterial(a)
	if err != nil {
		t.Fatal("reference graph cannot join original data", err)
	}
	if m.References.Publications["publication-example"].PreviousStatus != "failed" {
		t.Fatal("historical publication promoted to success")
	}
}

func TestReferenceExportRejectsMissingOrUnrelatedObjects(t *testing.T) {
	for name, change := range map[string]func(*testing.T, *sql.DB, *archive){
		"missing node": func(t *testing.T, db *sql.DB, a *archive) {
			if _, err := db.Exec("UPDATE applications SET node_id='missing-node' WHERE id='entry-example'"); err != nil {
				t.Fatal(err)
			}
		},
		"unrelated app": func(t *testing.T, db *sql.DB, a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "application_id", cell{Kind: "text", Text: "unrelated-app"})
		},
		"unknown selection field": func(t *testing.T, db *sql.DB, a *archive) {
			if _, err := db.Exec(`UPDATE settings SET value='{"nodeIds":[],"revision":1,"unknown":true}' WHERE key='meridian_landing_selection'`); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			db, a := referenceFixture(t)
			change(t, db, &a)
			if _, err := readReferences(context.Background(), db, a); err == nil {
				t.Fatal("invalid graph exported")
			}
		})
	}
}
