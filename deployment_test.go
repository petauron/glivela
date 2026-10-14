package meridian

import (
	"strings"
	"testing"
)

func TestAppliedReceiptBindsRevisionAndRenderedConfiguration(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000001"
	credential := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}
	desired, err := BuildDesiredArtifact(XrayPlan{
		Revision:         3,
		RealityEndpoints: []RealityEndpoint{{ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443, Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}}},
		Credentials:      []CredentialMaterial{{Credential: credential, ProtocolID: identifier}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAppliedReceipt(desired, AppliedReceipt{Revision: 3, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAppliedReceipt(desired, AppliedReceipt{Revision: 2, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}); err == nil {
		t.Fatal("stale receipt was accepted")
	}
}

func TestParseXrayUserCountersMatchesCompleteDelimiterBearingName(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000001"
	credential := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "team>>>phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}
	snapshots, err := ParseXrayUserCounters(
		[]CredentialMaterial{{Credential: credential, ProtocolID: identifier}},
		[]byte(`{"stat":[{"name":"user>>>team>>>phone>>>traffic>>>uplink","value":25},{"name":"user>>>team>>>phone>>>traffic>>>downlink","value":"30"}]}`),
	)
	if err != nil || len(snapshots) != 1 || snapshots[0].TotalBytes() != 55 {
		t.Fatalf("snapshots=%#v err=%v", snapshots, err)
	}
}

func TestParseXrayUserCountersRejectsNegativeValues(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000001"
	credential := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}
	_, err := ParseXrayUserCounters([]CredentialMaterial{{Credential: credential, ProtocolID: identifier}}, []byte(`{"stat":[{"name":"user>>>phone>>>traffic>>>uplink","value":-1}]}`))
	if err == nil || !strings.Contains(err.Error(), "counter") {
		t.Fatalf("negative counter error=%v", err)
	}
}

func TestParseXrayUserCountersAcceptsOmittedZeroValues(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000001"
	credential := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}
	snapshots, err := ParseXrayUserCounters(
		[]CredentialMaterial{{Credential: credential, ProtocolID: identifier}},
		[]byte(`{"stat":[{"name":"user>>>phone>>>traffic>>>uplink"},{"name":"user>>>phone>>>traffic>>>downlink","value":"15"}]}`),
	)
	if err != nil || len(snapshots) != 1 || snapshots[0].UpBytes != 0 || snapshots[0].DownBytes != 15 {
		t.Fatalf("snapshots=%#v err=%v", snapshots, err)
	}
}

func TestParseXrayUserCountersRejectsNullValues(t *testing.T) {
	_, err := ParseXrayUserCounters(nil, []byte(`{"stat":[{"name":"user>>>phone>>>traffic>>>uplink","value":null}]}`))
	if err == nil || !strings.Contains(err.Error(), "counter") {
		t.Fatalf("null counter error=%v", err)
	}
}

func TestParseXrayUserCountersAcceptsEmptyCredentialInventory(t *testing.T) {
	snapshots, err := ParseXrayUserCounters(nil, []byte(`{"stat":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("snapshots = %#v", snapshots)
	}
}
