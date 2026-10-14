package meridian

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRealityHostListenerPreservesPublicIdentity(t *testing.T) {
	endpoint := RealityEndpoint{ID: "entry", EntryID: "entry", InboundTag: "entry",
		ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort,
		AdvertiseHost: "entry.example.com", AdvertisePort: DefaultRealityPort,
		Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
		PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}}
	encoded, err := RenderXrayConfiguration(XrayPlan{Revision: 1, RealityEndpoints: []RealityEndpoint{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Listen   string
			Port     int
			Protocol string
		}
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 2 || config.Inbounds[0].Listen != "127.0.0.1" || config.Inbounds[0].Port != XrayAPIListenPort || config.Inbounds[1].Listen != endpoint.ListenAddress || config.Inbounds[1].Port != RealityBackendPort {
		t.Fatalf("host listeners: %+v", config.Inbounds)
	}
	identifier := "00000000-0000-4000-8000-000000000001"
	material := CredentialMaterial{Credential: Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}, ProtocolID: identifier}
	link, err := LinkForCredential(endpoint, material, "Entry")
	if err != nil || !strings.Contains(link, identifier+"@entry.example.com:443") || strings.Contains(link, "10443") || strings.Contains(link, endpoint.ListenAddress) {
		t.Fatalf("public subscription changed: %q %v", link, err)
	}
	for _, address := range []string{"", "0.0.0.0", "::", "127.0.0.1", "::1", "203.0.113.1", "100.64.0.2 "} {
		invalid := endpoint
		invalid.ListenAddress = address
		if invalid.Validate() == nil {
			t.Errorf("accepted unsafe backend address %q", address)
		}
	}
	endpoint.ListenPort = DefaultRealityPort
	if endpoint.Validate() == nil {
		t.Fatal("accepted privileged backend port")
	}
}
