package glivela

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func importEndpointFixture(t *testing.T) ImportEndpoint {
	t.Helper()
	hy2 := testHysteriaEndpoint(t)
	hy2.ID = "endpoint-a-hy2"
	hy2.EntryID = "entry-a"
	expires, err := HysteriaCertificateNotAfter(hy2)
	if err != nil {
		t.Fatal(err)
	}
	return ImportEndpoint{
		Reality:  RealityEndpoint{ID: "endpoint-a", EntryID: "entry-a", InboundTag: "inbound-a", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: hy2.AdvertiseHost, AdvertisePort: 443, Target: "www.example.com:443", ServerNames: []string{"www.example.com"}, PrivateKey: "original-private-key", PublicKey: "original-public-key", ShortIDs: []string{"abcd"}, Fingerprint: "chrome"},
		Hysteria: &hy2, ServiceID: "service-a", TargetIP: "203.0.113.20", VLESSEnabled: true, HysteriaEnabled: false,
		TotalBytes: 9007199254740993, UsedBytes: 987654321, QuotaAppliedEnabled: false, ResetDay: 19,
		ResetSchedule:   ImportResetSchedule{NextResetAt: "2026-11-19T00:00:00+08:00", LastResetAt: "2026-10-19T00:00:00+08:00"},
		DesiredRevision: 9, AppliedRevision: 8, HistoricalHealthy: true, PreviousStatus: "failed", PreviousError: "synthetic historical failure", LegacyRetired: true,
		SourcePeerJSON: json.RawMessage(`{"id":"peer-example","address":"100.64.0.2"}`), CertificateNotAfter: expires.Format(time.RFC3339Nano), CreatedAt: "2026-09-19T00:00:00Z", UpdatedAt: "2026-10-19T02:03:04.123456789Z",
	}
}

func TestEndpointImportRetainsDisabledConfigurationAndHistoricalState(t *testing.T) {
	m := importFixture(t)
	e := importEndpointFixture(t)
	if err := ValidateEndpointImport(m, []ImportEndpoint{e}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got ImportEndpoint
	if err := json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(e, got) {
		t.Fatal("endpoint configuration changed", err)
	}
	if got.HysteriaEnabled || got.Hysteria == nil || got.Hysteria.PrivateKeyPEM != e.Hysteria.PrivateKeyPEM || got.PreviousStatus != "failed" || got.AppliedRevision != 8 || got.TotalBytes != 9007199254740993 || got.ResetSchedule != e.ResetSchedule {
		t.Fatal("configuration initialized or historical state promoted")
	}
}

func TestEndpointImportPreservesRetiredEndpointConfiguration(t *testing.T) {
	e := importEndpointFixture(t)
	e.PreviousStatus = "retired"
	if err := ValidateEndpointImport(importFixture(t), []ImportEndpoint{e}); err != nil {
		t.Fatal("retired endpoint was discarded", err)
	}
	if !e.VLESSEnabled || e.HysteriaEnabled || e.PreviousStatus != "retired" {
		t.Fatal("retirement reset protocol configuration")
	}
}

func TestEndpointImportRejectsLostOrChangedReferences(t *testing.T) {
	for name, change := range map[string]func(*ImportEndpoint){
		"entry identity":       func(e *ImportEndpoint) { e.Reality.EntryID = "other-entry" },
		"listen exposure":      func(e *ImportEndpoint) { e.Reality.ListenAddress = "0.0.0.0" },
		"quota":                func(e *ImportEndpoint) { e.UsedBytes = -1 },
		"cycle":                func(e *ImportEndpoint) { e.ResetDay = 32 },
		"revision":             func(e *ImportEndpoint) { e.AppliedRevision = e.DesiredRevision + 1 },
		"missing Hysteria":     func(e *ImportEndpoint) { e.Hysteria = nil; e.CertificateNotAfter = "" },
		"certificate expiry":   func(e *ImportEndpoint) { e.CertificateNotAfter = "2000-01-01T00:00:00Z" },
		"certificate identity": func(e *ImportEndpoint) { e.Hysteria.ServerName = "different.example.test" },
		"metadata":             func(e *ImportEndpoint) { e.SourcePeerJSON = json.RawMessage(`[]`) },
		"both disabled":        func(e *ImportEndpoint) { e.VLESSEnabled = false; e.HysteriaEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			e := importEndpointFixture(t)
			change(&e)
			if ValidateEndpointImport(importFixture(t), []ImportEndpoint{e}) == nil {
				t.Fatal("incomplete or changed endpoint accepted")
			}
		})
	}
	e := importEndpointFixture(t)
	if ValidateEndpointImport(importFixture(t), nil) == nil || ValidateEndpointImport(importFixture(t), []ImportEndpoint{e, e}) == nil {
		t.Fatal("missing or duplicate endpoint accepted")
	}
}
