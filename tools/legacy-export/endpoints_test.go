package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func completeEndpointArchiveFixture(t *testing.T) archive {
	t.Helper()
	a := accountRowsFixture()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hy.example.test"}, DNSNames: []string{"hy.example.test"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	a.Secrets["endpoint-key"] = secretValue{Context: "meridian-endpoint:endpoint-example", Value: []byte("original-reality-private-key")}
	a.Secrets["hy2-cert"] = secretValue{Context: "meridian-hy2-certificate:endpoint-example", Value: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	a.Secrets["hy2-key"] = secretValue{Context: "meridian-hy2-private-key:endpoint-example", Value: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	a.Tables["meridian_endpoints"] = tableFixture(map[string]any{
		"id": "endpoint-example", "application_id": "entry-example", "service_id": "service-example", "inbound_tag": "inbound-example",
		"listen_address": "100.64.0.2", "listen_port": 10443, "advertise_host": "entry.example.test", "advertise_port": 443, "target": "www.example.com:443", "target_ip": "203.0.113.20",
		"server_names_json": "[\"www.example.com\"]", "private_key_secret_id": "endpoint-key", "public_key": "original-reality-public-key", "short_ids_json": "[\"abcd\"]", "fingerprint": "chrome",
		"vless_enabled": 1, "hy2_enabled": 0, "hy2_inbound_tag": "hy2-example", "hy2_server_name": "hy.example.test", "hy2_certificate_secret_id": "hy2-cert", "hy2_private_key_secret_id": "hy2-key", "hy2_certificate_not_after": expires.Format(time.RFC3339),
		"total_bytes": int64(9007199254740993), "used_bytes": int64(987654321), "quota_applied_enabled": 0, "reset_day": 19, "next_reset_at": "2026-11-19T00:00:00+08:00", "last_reset_at": "2026-10-19T00:00:00+08:00",
		"desired_revision": 9, "applied_revision": 8, "runtime_healthy": 1, "legacy_retired": 1, "status": "failed", "last_error": "synthetic historical failure", "created_at": "2026-09-19T00:00:00Z", "updated_at": "2026-10-19T02:03:04.123456789Z", "source_peer_json": "{\"id\":\"example-peer\",\"address\":\"100.64.0.2\"}",
	})
	a.Tables["meridian_route_health_events"] = tableFixture(map[string]any{"id": 17, "route_id": "grant-example", "recorded_at": "2026-10-19T02:03:04Z", "fingerprint": glivela.Identity("synthetic-history"), "diagnostics_json": "{\"state\":\"failed\",\"reason\":\"synthetic\"}"})
	a.References = glivela.ImportReferences{
		Nodes:            map[string]glivela.ImportNode{"entry-host-example": {Name: "Entry host", PreviousStatus: "active", ServiceAddress: "100.64.0.2", PrivateAddress: "100.64.0.2"}, "landing-example": {Name: "Landing host", PreviousStatus: "disabled", PrivateAddress: "100.64.0.3"}},
		Applications:     map[string]glivela.ImportApplication{"entry-example": {Name: "Existing proxy", NodeID: "entry-host-example", Runtime: "docker", PreviousStatus: "running"}},
		Services:         map[string]glivela.ImportService{"service-example": {ApplicationID: "entry-example", Name: "entry", DisplayName: "Saved entry", RegionCode: "US", Protocol: "tcp", ApplicationProtocol: "meridian/entry", ContainerPort: 10443, HostPort: 443, Endpoint: "100.64.0.2:10443", PreviousStatus: "ready"}},
		Publications:     map[string]glivela.ImportPublication{"publication-example": {ServiceID: "service-example", EntryNodeID: "entry-host-example", Kind: "public_shared_443", IngressOwner: "application_node", Hostname: "entry.example.test", SNIHostname: "www.example.com", DNSProvider: "manual", DesiredRevision: 3, AppliedRevision: 2, PreviousStatus: "failed", PreviousError: "synthetic error", CreatedAt: "2026-09-19T00:00:00Z", UpdatedAt: "2026-10-19T02:03:04Z"}},
		LandingSelection: &glivela.ImportLandingSelection{NodeIDs: []string{"landing-example"}, LandingRegionCodes: map[string]string{"landing-example": "US"}, LandingNameSuffixes: map[string]string{"landing-example": "Saved"}, Revision: 7},
	}
	service := a.References.Services["service-example"]
	service.Timezone = "Asia/Shanghai"
	a.References.Services["service-example"] = service
	return a
}

func TestEndpointConversionRetainsOriginalConfiguration(t *testing.T) {
	a := completeEndpointArchiveFixture(t)
	items, err := endpointMaterial(a)
	if err != nil || len(items) != 1 {
		t.Fatal("endpoint conversion failed", err)
	}
	m, err := importMaterial(a)
	if err != nil || glivela.ValidateEndpointImport(m, items) != nil {
		t.Fatal("complete inventory failed", err)
	}
	e := items[0]
	want := glivela.ImportEndpoint{
		Reality:   glivela.RealityEndpoint{ID: "endpoint-example", EntryID: "entry-example", InboundTag: "inbound-example", ListenAddress: "100.64.0.2", ListenPort: 10443, AdvertiseHost: "entry.example.test", AdvertisePort: 443, Target: "www.example.com:443", ServerNames: []string{"www.example.com"}, PrivateKey: string(a.Secrets["endpoint-key"].Value), PublicKey: "original-reality-public-key", ShortIDs: []string{"abcd"}, Fingerprint: "chrome"},
		Hysteria:  &glivela.HysteriaEndpoint{ID: "endpoint-example-hy2", EntryID: "entry-example", InboundTag: "hy2-example", ListenPort: 443, AdvertiseHost: "entry.example.test", AdvertisePort: 443, ServerName: "hy.example.test", CertificatePEM: string(a.Secrets["hy2-cert"].Value), PrivateKeyPEM: string(a.Secrets["hy2-key"].Value)},
		ServiceID: "service-example", TargetIP: "203.0.113.20", VLESSEnabled: true, HysteriaEnabled: false, TotalBytes: 9007199254740993, UsedBytes: 987654321, QuotaAppliedEnabled: false, ResetDay: 19, ResetSchedule: glivela.ImportResetSchedule{NextResetAt: "2026-11-19T00:00:00+08:00", LastResetAt: "2026-10-19T00:00:00+08:00"}, DesiredRevision: 9, AppliedRevision: 8, HistoricalHealthy: true, PreviousStatus: "failed", PreviousError: "synthetic historical failure", LegacyRetired: true, SourcePeerJSON: json.RawMessage(`{"id":"example-peer","address":"100.64.0.2"}`), CertificateNotAfter: "2030-01-01T00:00:00Z", CreatedAt: "2026-09-19T00:00:00Z", UpdatedAt: "2026-10-19T02:03:04.123456789Z",
	}
	if !reflect.DeepEqual(e, want) {
		t.Fatal("complete endpoint record differs after conversion")
	}
	if e.Reality.ID != "endpoint-example" || e.Reality.EntryID != "entry-example" || e.ServiceID != "service-example" || e.Reality.PrivateKey != string(a.Secrets["endpoint-key"].Value) || e.Hysteria == nil || e.Hysteria.PrivateKeyPEM != string(a.Secrets["hy2-key"].Value) || e.HysteriaEnabled {
		t.Fatal("identity/key/disabled configuration changed")
	}
	if e.TotalBytes != 9007199254740993 || e.ResetDay != 19 || e.ResetSchedule.NextResetAt != "2026-11-19T00:00:00+08:00" || e.PreviousStatus != "failed" || e.AppliedRevision != 8 || !e.HistoricalHealthy || e.QuotaAppliedEnabled {
		t.Fatal("quota/cycle/historical observations were reinitialized")
	}
	// BLOB and TEXT are both legitimate SQLite storage for JSON columns.
	for _, column := range []string{"server_names_json", "short_ids_json", "source_peer_json"} {
		r := a.Tables["meridian_endpoints"]
		for i, name := range r.Columns {
			if name == column {
				r.Rows[0][i] = cell{Kind: "blob", Blob: []byte(r.Rows[0][i].Text)}
			}
		}
		a.Tables["meridian_endpoints"] = r
	}
	blob, err := endpointMaterial(a)
	if err != nil || !reflect.DeepEqual(items, blob) {
		t.Fatal("legitimate JSON storage changed interpretation", err)
	}
}

func realLegacyAccountArchive(t *testing.T) (archive, bool) {
	t.Helper()
	dir := os.Getenv("GLIVELA_ACCOUNT_FIXTURE_DIR")
	if dir == "" {
		t.Skip("anonymous old-source fixture not supplied")
		return archive{}, false
	}
	key, err := privateFile(filepath.Join(dir, "transfer.key"), 32)
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	defer clear(key)
	sealed, err := privateFile(filepath.Join(dir, "legacy.sealed"), maxSnapshotBytes+64)
	if err != nil {
		t.Fatal("fixture archive unavailable")
	}
	a, err := openArchive(sealed, key, "actual-accounts-example")
	if err != nil {
		t.Fatal("fixture authentication failed")
	}
	return a, true
}

func TestEndpointConversionRejectsMissingAndMismatchedData(t *testing.T) {
	for name, change := range map[string]func(*archive){
		"key owner": func(a *archive) {
			s := a.Secrets["endpoint-key"]
			s.Context = "meridian-endpoint:other"
			a.Secrets["endpoint-key"] = s
		},
		"missing certificate": func(a *archive) { delete(a.Secrets, "hy2-cert") },
		"changed certificate expiry": func(a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "hy2_certificate_not_after", cell{Kind: "text", Text: "2000-01-01T00:00:00Z"})
		},
		"port overflow": func(a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "listen_port", cell{Kind: "integer", Text: "9223372036854775807"})
		},
		"reset overflow": func(a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "reset_day", cell{Kind: "integer", Text: "9223372036854775807"})
		},
		"untyped JSON": func(a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "server_names_json", cell{Kind: "integer", Text: "1"})
		},
		"wrong JSON": func(a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "short_ids_json", cell{Kind: "text", Text: "{}"})
		},
		"hidden disabled config": func(a *archive) {
			replaceCell(a, "meridian_endpoints", 0, "hy2_inbound_tag", cell{Kind: "text", Text: ""})
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := completeEndpointArchiveFixture(t)
			change(&a)
			if _, err := endpointMaterial(a); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
		})
	}
}

func TestRealLegacyEndpointFixture(t *testing.T) {
	// The account fixture test loads and decrypts this same old-source backup;
	// this opt-in companion independently checks its complete endpoint model.
	a, ok := realLegacyAccountArchive(t)
	if !ok {
		return
	}
	items, err := endpointMaterial(a)
	if err != nil || len(items) != 1 {
		t.Fatal("real endpoint conversion failed", err)
	}
	m, err := importMaterial(a)
	if err != nil || glivela.ValidateEndpointImport(m, items) != nil {
		t.Fatal("real endpoint inventory differs", err)
	}
	e := items[0]
	if e.Reality.ID != "snapshot-shared-endpoint" || e.Reality.EntryID != "snapshot-shared-app" || e.ServiceID != "snapshot-shared-service" || e.Reality.PrivateKey != "test-private-key" || e.Reality.PublicKey != "test-public-key" {
		t.Fatal("real endpoint identity/configuration changed")
	}
	if !json.Valid(e.SourcePeerJSON) || e.Hysteria != nil || e.HysteriaEnabled {
		t.Fatal("real endpoint initialized unsupported configuration")
	}
}
