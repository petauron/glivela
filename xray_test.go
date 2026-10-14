package meridian

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestRenderXrayConfigurationProjectsNativeAndFixedCredentials(t *testing.T) {
	nativeID := "00000000-0000-4000-8000-000000000001"
	routeID := "00000000-0000-4000-8000-000000000002"
	native := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(nativeID), EntryID: "entry", Enabled: true}
	route := Credential{ID: "route", AccountID: "account", Kind: RouteCredential, User: RouteUser("grant"), Identity: Identity(routeID), EntryID: "entry", EgressID: "egress", Enabled: true}
	grant := RouteGrant{ID: "grant", AccountID: "account", EntryID: "entry", EgressID: "egress", InboundTag: "meridian-entry", Base: native, Route: route, Mode: FixedMode, Enabled: true, DesiredRev: 2, AppliedRev: 1}
	encoded, err := RenderXrayConfiguration(XrayPlan{
		Revision:         2,
		RealityEndpoints: []RealityEndpoint{{ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443, Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}, Fingerprint: "chrome"}},
		Credentials:      []CredentialMaterial{{Credential: native, ProtocolID: nativeID}, {Credential: route, ProtocolID: routeID}},
		Grants:           []RouteGrant{grant},
		Peers:            []RoutePeer{{EgressID: "egress", Address: "100.64.0.10", Port: 1080}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(encoded, &config) != nil || len(config.Inbounds) != 2 || len(config.Outbounds) != 3 || len(config.Routing.Rules) != 4 {
		t.Fatalf("unexpected Xray projection: %s", encoded)
	}
	stream := config.Inbounds[1]["streamSettings"].(map[string]any)
	sniffing, ok := config.Inbounds[1]["sniffing"].(map[string]any)
	if !ok || sniffing["enabled"] != true || sniffing["routeOnly"] != false {
		t.Fatal("resolved client IPs must be replaced by sniffed domains before forwarding to the fixed egress")
	}
	protocols, _ := json.Marshal(sniffing["destOverride"])
	if string(protocols) != `["http","tls"]` || config.Inbounds[0]["sniffing"] != nil {
		t.Fatal("domain recovery must cover HTTP/TLS without changing the management inbound")
	}
	raw, ok := stream["rawSettings"].(map[string]any)
	if config.Inbounds[1]["listen"] != "100.64.0.2" || stream["security"] != "reality" || stream["method"] != "raw" || !ok || raw["acceptProxyProtocol"] != true || stream["network"] != nil || stream["tcpSettings"] != nil || stream["sockopt"] != nil {
		t.Fatalf("REALITY host backend contract missing: %#v", config.Inbounds[1])
	}
	if config.Routing.Rules[2]["outboundTag"] != routeOutboundTag("grant") || config.Routing.Rules[3]["outboundTag"] != "blocked" {
		t.Fatalf("fixed route is not fail closed: %#v", config.Routing.Rules)
	}
}

func TestRenderXrayConfigurationAcceptsEmptyAccountInventory(t *testing.T) {
	endpoint := RealityEndpoint{
		ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry",
		ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443,
		Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
		PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"},
	}
	encoded, err := RenderXrayConfiguration(XrayPlan{Revision: 1, RealityEndpoints: []RealityEndpoint{endpoint}})
	if err != nil {
		t.Fatalf("RenderXrayConfiguration() error = %v", err)
	}
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Clients []any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == endpoint.InboundTag {
			if inbound.Settings.Clients == nil || len(inbound.Settings.Clients) != 0 {
				t.Fatalf("empty account clients = %#v", inbound.Settings.Clients)
			}
			return
		}
	}
	t.Fatal("REALITY inbound was not rendered")
}

func TestRenderXrayConfigurationRejectsOrphanedRouteCredential(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000002"
	route := Credential{ID: "route", AccountID: "account", Kind: RouteCredential, User: RouteUser("grant"), Identity: Identity(identifier), EntryID: "entry", EgressID: "egress", Enabled: true}
	_, err := RenderXrayConfiguration(XrayPlan{
		Revision:         1,
		RealityEndpoints: []RealityEndpoint{{ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443, Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}}},
		Credentials:      []CredentialMaterial{{Credential: route, ProtocolID: identifier}},
	})
	if err == nil || !strings.Contains(err.Error(), "orphaned") {
		t.Fatalf("orphaned route credential error = %v", err)
	}
}

func TestLinkForCredentialPreservesSecretIdentity(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000001"
	credential := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}
	link, err := LinkForCredential(
		RealityEndpoint{ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443, Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}},
		CredentialMaterial{Credential: credential, ProtocolID: identifier},
		"🇺🇸｜Entry Alpha",
	)
	if err != nil || !strings.Contains(link, identifier+"@entry.example.com:443") || !strings.HasSuffix(link, "#🇺🇸｜Entry%20Alpha") {
		t.Fatalf("link=%q err=%v", link, err)
	}
}

func TestSubscriptionLinksDoNotRequireRuntimePrivateKeys(t *testing.T) {
	identifier := "00000000-0000-4000-8000-000000000001"
	credential := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "phone", Identity: Identity(identifier), EntryID: "entry", Enabled: true}
	material := CredentialMaterial{Credential: credential, ProtocolID: identifier, HysteriaAuth: "hy2-secret", HysteriaIdentity: Identity("hy2-secret")}
	if _, err := LinkForCredential(RealityEndpoint{
		ID: "endpoint", EntryID: "entry", AdvertiseHost: "entry.example.com", AdvertisePort: 443,
		ServerNames: []string{"www.microsoft.com"}, PublicKey: "public", ShortIDs: []string{"0123456789abcdef"},
	}, material, "Entry"); err != nil {
		t.Fatalf("public REALITY projection rejected: %v", err)
	}
	if _, err := Hysteria2LinkForCredential(HysteriaEndpoint{
		ID: "endpoint-hy2", EntryID: "entry", AdvertiseHost: "entry.example.com", AdvertisePort: 443, ServerName: "hy.example.com",
	}, material, "Entry · HY2"); err != nil {
		t.Fatalf("public Hysteria projection rejected: %v", err)
	}
}

func TestRenderXrayConfigurationKeepsHysteriaNativeWhenVLESSIsRouted(t *testing.T) {
	nativeID := "00000000-0000-4000-8000-000000000011"
	routeID := "00000000-0000-4000-8000-000000000012"
	native := Credential{ID: "native", AccountID: "account", Kind: NativeCredential, User: "account-native", Identity: Identity(nativeID), EntryID: "entry", Enabled: true}
	route := Credential{ID: "route", AccountID: "account", Kind: RouteCredential, User: RouteUser("grant"), Identity: Identity(routeID), EntryID: "entry", EgressID: "egress", Enabled: true}
	grant := RouteGrant{ID: "grant", AccountID: "account", EntryID: "entry", EgressID: "egress", InboundTag: "meridian-entry", Base: native, Route: route, Mode: FixedMode, Enabled: true, DesiredRev: 2, AppliedRev: 1}
	hy2 := testHysteriaEndpoint(t)
	encoded, err := RenderXrayConfiguration(XrayPlan{
		Revision:          2,
		RealityEndpoints:  []RealityEndpoint{{ID: "endpoint", EntryID: "entry", InboundTag: "meridian-entry", ListenAddress: "100.64.0.2", ListenPort: RealityBackendPort, AdvertiseHost: "entry.example.com", AdvertisePort: 443, Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, PrivateKey: "private", PublicKey: "public", ShortIDs: []string{"0123456789abcdef"}, Fingerprint: "chrome"}},
		HysteriaEndpoints: []HysteriaEndpoint{hy2},
		Credentials: []CredentialMaterial{
			{Credential: native, ProtocolID: nativeID, HysteriaAuth: "native-hy2-secret", HysteriaIdentity: Identity("native-hy2-secret")},
			{Credential: route, ProtocolID: routeID},
		},
		Grants: []RouteGrant{grant},
		Peers:  []RoutePeer{{EgressID: "egress", Address: "100.64.0.10", Port: 1080}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []map[string]any `json:"inbounds"`
		Routing  struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(encoded, &config) != nil || len(config.Inbounds) != 3 {
		t.Fatalf("unexpected dual-protocol configuration: %s", encoded)
	}
	hy2Inbound := config.Inbounds[2]
	users := hy2Inbound["settings"].(map[string]any)["users"].([]any)
	firstUser := users[0].(map[string]any)
	stream := hy2Inbound["streamSettings"].(map[string]any)
	transport := stream["hysteriaSettings"].(map[string]any)
	if hy2Inbound["protocol"] != "hysteria" || firstUser["email"] != native.User || firstUser["auth"] != "native-hy2-secret" || firstUser["level"] != float64(0) || stream["method"] != "hysteria" || transport["auth"] != nil {
		t.Fatalf("unexpected Hysteria client projection: %#v", hy2Inbound)
	}
	inboundTags := config.Routing.Rules[1]["inboundTag"].([]any)
	if len(inboundTags) != 1 || inboundTags[0] != "meridian-entry" || len(users) != 1 {
		t.Fatalf("route escaped the VLESS-only boundary: %#v", config.Routing.Rules[1])
	}
}

func testHysteriaEndpoint(t *testing.T) HysteriaEndpoint {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hy.example.com"},
		DNSNames:     []string{"hy.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return HysteriaEndpoint{
		ID: "endpoint-hy2", EntryID: "entry", InboundTag: "meridian-entry-hy2",
		ListenPort: 443, AdvertiseHost: "entry.example.com", AdvertisePort: 443,
		ServerName:     "hy.example.com",
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
	}
}
