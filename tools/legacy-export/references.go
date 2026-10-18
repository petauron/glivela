package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"slices"

	glivela "github.com/petauron/glivela"
)

// Read only the proxy application's reference graph. In particular, never
// select agent credentials, platform authentication or shared provider tokens.
func readReferences(ctx context.Context, db *sql.DB, a archive) (glivela.ImportReferences, error) {
	r := glivela.ImportReferences{Nodes: map[string]glivela.ImportNode{}, Applications: map[string]glivela.ImportApplication{}, Services: map[string]glivela.ImportService{}, Publications: map[string]glivela.ImportPublication{}}
	var selection []byte
	err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='meridian_landing_selection'").Scan(&selection)
	if err == nil {
		if len(selection) > 64<<10 {
			return r, errors.New("selection too large")
		}
		decoder := json.NewDecoder(bytes.NewReader(selection))
		decoder.DisallowUnknownFields()
		var s glivela.ImportLandingSelection
		var extra any
		if decoder.Decode(&s) != nil || decoder.Decode(&extra) != io.EOF {
			return r, errors.New("invalid landing selection")
		}
		r.LandingSelection = &s
	} else if !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	appIDs, nodeIDs := map[string]bool{}, map[string]bool{}
	for name, columns := range map[string][]string{
		"meridian_endpoints": {"application_id"}, "meridian_cutover": {"legacy_controller_application_id"},
		"landing_proxy_states": {"application_id"}, "landing_client_grants": {"application_id"},
	} {
		if err := referenceIDs(a.Tables[name], columns, appIDs); err != nil {
			return r, err
		}
	}
	for name, columns := range map[string][]string{
		"landing_server_states": {"node_id"}, "landing_proxy_states": {"node_id", "landing_node_id"},
		"landing_proxy_retirements": {"node_id", "landing_node_id"}, "landing_client_grants": {"landing_node_id"},
		"meridian_credentials": {"egress_node_id"}, "meridian_route_grants": {"egress_node_id", "ipv4_egress_node_id"}, "node_egress_policies": {"node_id"},
	} {
		if err := referenceIDs(a.Tables[name], columns, nodeIDs); err != nil {
			return r, err
		}
	}
	if s := r.LandingSelection; s != nil {
		for _, ids := range [][]string{s.NodeIDs, s.RetiringNodeIDs} {
			for _, id := range ids {
				nodeIDs[id] = true
			}
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT id,name,node_id,runtime,status FROM applications WHERE app_key='vastora-official/meridian' ORDER BY id")
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var id string
		var app glivela.ImportApplication
		if err := rows.Scan(&id, &app.Name, &app.NodeID, &app.Runtime, &app.PreviousStatus); err != nil {
			rows.Close()
			return r, err
		}
		r.Applications[id] = app
		appIDs[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	for id := range appIDs {
		if _, ok := r.Applications[id]; !ok {
			var app glivela.ImportApplication
			var key string
			if err := db.QueryRowContext(ctx, "SELECT name,node_id,runtime,status,app_key FROM applications WHERE id=?", id).Scan(&app.Name, &app.NodeID, &app.Runtime, &app.PreviousStatus, &key); err != nil {
				return r, err
			}
			if key != "vastora-official/meridian" && key != "vastora-official/3x-ui" {
				return r, errors.New("proxy reference points to an unrelated application")
			}
			r.Applications[id] = app
		}
		nodeIDs[r.Applications[id].NodeID] = true
		if err := readReferencedServices(ctx, db, id, r.Services); err != nil {
			return r, err
		}
	}
	for id := range r.Services {
		if err := readReferencedPublications(ctx, db, id, r.Publications, nodeIDs); err != nil {
			return r, err
		}
	}
	for id := range nodeIDs {
		if !glivela.ValidIdentifier(id) {
			return r, errors.New("invalid node reference")
		}
		var n glivela.ImportNode
		var egressJSON, peerJSON []byte
		if err := db.QueryRowContext(ctx, "SELECT name,status,landing_egress_addresses_json FROM agents WHERE id=?", id).Scan(&n.Name, &n.PreviousStatus, &egressJSON); err != nil {
			return r, err
		}
		n.EgressAddressesJSON = egressJSON
		err := db.QueryRowContext(ctx, "SELECT service_address,headscale_address FROM agent_network_profiles WHERE agent_id=?", id).Scan(&n.ServiceAddress, &n.PrivateAddress)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return r, err
		}
		err = db.QueryRowContext(ctx, "SELECT peer_json FROM agent_private_peer_capabilities WHERE node_id=?", id).Scan(&peerJSON)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return r, err
		}
		n.PeerJSON = peerJSON
		r.Nodes[id] = n
	}
	return r, nil
}

func referenceIDs(t table, columns []string, ids map[string]bool) error {
	for _, row := range t.Rows {
		if len(row) != len(t.Columns) {
			return errors.New("invalid reference row")
		}
		for _, column := range columns {
			i := slices.Index(t.Columns, column)
			if i < 0 {
				return errors.New("reference column missing")
			}
			v := row[i]
			if v.Kind == "null" {
				continue
			}
			if v.Kind != "text" || !glivela.ValidIdentifier(v.Text) {
				return errors.New("invalid object reference")
			}
			ids[v.Text] = true
		}
	}
	return nil
}

func readReferencedServices(ctx context.Context, db *sql.DB, appID string, services map[string]glivela.ImportService) error {
	rows, err := db.QueryContext(ctx, `SELECT id,application_id,name,display_name,region_code,protocol,app_protocol,container_port,host_port,endpoint,status FROM services WHERE application_id=? AND (app_protocol IN ('meridian/entry','meridian/subscription') OR name='subscription' OR id IN (SELECT service_id FROM meridian_endpoints) OR id IN (SELECT service_id FROM landing_client_grants)) ORDER BY id`, appID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s glivela.ImportService
		if err := rows.Scan(&id, &s.ApplicationID, &s.Name, &s.DisplayName, &s.RegionCode, &s.Protocol, &s.ApplicationProtocol, &s.ContainerPort, &s.HostPort, &s.Endpoint, &s.PreviousStatus); err != nil {
			return err
		}
		services[id] = s
	}
	return rows.Err()
}

func readReferencedPublications(ctx context.Context, db *sql.DB, serviceID string, publications map[string]glivela.ImportPublication, nodes map[string]bool) error {
	rows, err := db.QueryContext(ctx, `SELECT id,service_id,entry_node_id,kind,ingress_owner,hostname,sni_hostname,dns_provider,dns_record_id,access_application_id,tls_enabled,desired_revision,applied_revision,status,last_error,action_required,cleanup_pending,cleanup_attempt,cleanup_retry_at,created_at,updated_at FROM publications WHERE service_id=? ORDER BY id`, serviceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var p glivela.ImportPublication
		if err := rows.Scan(&id, &p.ServiceID, &p.EntryNodeID, &p.Kind, &p.IngressOwner, &p.Hostname, &p.SNIHostname, &p.DNSProvider, &p.DNSRecordID, &p.AccessApplicationID, &p.TLSEnabled, &p.DesiredRevision, &p.AppliedRevision, &p.PreviousStatus, &p.PreviousError, &p.ActionRequired, &p.CleanupPending, &p.CleanupAttempt, &p.CleanupRetryAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return err
		}
		publications[id] = p
		nodes[p.EntryNodeID] = true
	}
	return rows.Err()
}
