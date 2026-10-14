package meridian

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestNativeEgressChangesOnlyTheDirectOutbound(t *testing.T) {
	plan := egressPlanFixture()
	original, err := RenderXrayConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.NativeEgress = EgressAuto
	automatic, err := RenderXrayConfiguration(plan)
	if err != nil || !bytes.Equal(original, automatic) {
		t.Fatal("automatic policy changed existing proxy configuration")
	}
	var before map[string]any
	if err := json.Unmarshal(original, &before); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []EgressPolicy{EgressIPv4Only, EgressIPv6Only} {
		t.Run(string(policy), func(t *testing.T) {
			plan.NativeEgress = policy
			artifact, err := BuildDesiredArtifact(plan)
			if err != nil || artifact.Validate() != nil {
				t.Fatalf("invalid artifact: %v", err)
			}
			var after map[string]any
			if err := json.Unmarshal(artifact.Config, &after); err != nil {
				t.Fatal(err)
			}
			outbounds := after["outbounds"].([]any)
			if reflect.DeepEqual(outbounds[0], before["outbounds"].([]any)[0]) {
				t.Fatal("native policy was ignored")
			}
			outbounds[0] = before["outbounds"].([]any)[0]
			if !reflect.DeepEqual(before, after) {
				t.Fatal("native policy changed a credential, public entry, API or fixed landing route")
			}
		})
	}
}

func TestNativeEgressRejectsUnknownPolicy(t *testing.T) {
	plan := egressPlanFixture()
	for _, policy := range []EgressPolicy{"ipv6", "prefer_ipv4", "prefer_ipv6", "AUTO", " auto"} {
		plan.NativeEgress = policy
		if _, err := BuildDesiredArtifact(plan); err == nil {
			t.Errorf("unsupported policy %q silently used automatic egress", policy)
		}
	}
}

func egressPlanFixture() XrayPlan {
	nativeID, routeID := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	native := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(nativeID), EntryID: "entry", Enabled: true}
	route := Credential{ID: "route", AccountID: "account", Kind: RouteCredential, User: RouteUser("grant"), Identity: Identity(routeID), EntryID: "entry", EgressID: "egress", Enabled: true}
	return XrayPlan{
		Revision: 2,
		RealityEndpoints: []RealityEndpoint{{ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry",
			ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443,
			Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}}},
		Credentials: []CredentialMaterial{{Credential: native, ProtocolID: nativeID}, {Credential: route, ProtocolID: routeID}},
		Grants: []RouteGrant{{ID: "grant", AccountID: "account", EntryID: "entry", EgressID: "egress", InboundTag: "meridian-entry",
			Base: native, Route: route, Mode: FixedMode, Enabled: true, DesiredRev: 2, AppliedRev: 1}},
		Peers: []RoutePeer{{EgressID: "egress", Address: "100.64.0.10", Port: 1080}},
	}
}
