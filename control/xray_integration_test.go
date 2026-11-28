package control

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// Uses an independently verified official binary. No production network,
// systemd service, firewall or existing application is touched by this test.
func officialTestDriver(t *testing.T) SystemdDriver {
	t.Helper()
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if binary == "" {
		t.Skip("set GLIVELA_XRAY_BINARY to a verified official Xray")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	driver := SystemdDriver{Binary: binary, BinarySHA256: hex.EncodeToString(digest[:])}
	if distribution := os.Getenv("GLIVELA_DISTRIBUTION"); distribution != "" {
		verified, err := (SystemdDriver{Distribution: distribution}).resolveDistribution(runtime.GOOS, runtime.GOARCH)
		if err != nil || verified.Binary != driver.Binary || verified.BinarySHA256 != driver.BinarySHA256 {
			t.Fatal("packaged runtime metadata does not identify the tested core", err)
		}
		driver = verified
	}
	return driver
}

func TestOfficialXrayValidationAndTLS(t *testing.T) {
	driver := officialTestDriver(t)
	binary := driver.Binary
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	path := filepath.Join(t.TempDir(), "configuration.json")
	// Loopback forwarding is intentional in this isolated fixture; production
	// landing safety rules must be validated separately, not weakened for it.
	// Exercise a mixed resolver inventory larger than the legacy adapter's
	// address window. The IPv4 result must remain usable even when it is last.
	var records []string
	for i := 1; i <= 12; i++ {
		records = append(records, fmt.Sprintf("2001:db8::%x", i))
	}
	records = append(records, "127.0.0.1")
	hosts, err := json.Marshal(map[string][]string{"example.com": records})
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"dns":{"hosts":%s,"queryStrategy":"UseIPv4"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]}`, hosts, port)
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = validateXrayFile(ctx, driver.Binary, driver.BinarySHA256, path); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "run", "-format", "json", "-config", path)
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer target.Close()
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	if err := target.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal("TLS fixture lacks domain identity", err)
	}
	domainURL := strings.Replace(target.URL, "127.0.0.1", "example.com", 1)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = probeSOCKSTLS(ctx, address, target.URL, pool)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := probeSOCKSTLS(ctx, address, domainURL, pool); err != nil {
		t.Fatal("IPv4 SOCKS domain request failed with twelve preceding IPv6 records", err)
	}
	if probeSOCKSTLS(ctx, address, domainURL, nil) == nil {
		t.Fatal("domain request skipped certificate verification")
	}
	if probeSOCKSTLS(ctx, address, target.URL, nil) == nil {
		t.Fatal("untrusted TLS target accepted")
	}
	exitTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("203.0.113.9\n")) }))
	defer exitTarget.Close()
	pool.AddCert(exitTarget.Certificate())
	probe := RouteProbe{AttemptID: "attempt-example", SnapshotID: "snapshot-example", EntryID: "entry-example", LandingID: "landing-example", Revision: 7, ConfigSHA256: strings.Repeat("a", 64), SOCKSAddress: address, Target: strings.Replace(exitTarget.URL, "127.0.0.1", "example.com", 1), ExpectedExit: "203.0.113.9"}
	result, err := checkRoute(ctx, probe, pool)
	if err != nil || !result.Passed || !result.TLSVerified || result.HTTPStatus != 200 || result.Revision != 7 || result.SnapshotID != probe.SnapshotID {
		t.Fatal("entry-side route acceptance failed", err, result.Failure)
	}
	probe.ExpectedExit = "203.0.113.10"
	result, err = checkRoute(ctx, probe, pool)
	if err == nil || result.Passed || !result.TLSVerified || result.Failure != "exit-mismatch" {
		t.Fatal("wrong exit accepted")
	}
	probe.Target = domainURL
	result, err = checkRoute(ctx, probe, pool)
	if err == nil || result.Passed || !result.TLSVerified || result.HTTPStatus != 404 || result.Failure != "http-status" {
		t.Fatal("HTTP rejection confused with TLS failure")
	}
	result, err = checkRoute(ctx, probe, nil)
	if err == nil || result.Passed || result.TLSVerified || result.HTTPStatus != 0 {
		t.Fatal("untrusted certificate accepted by route check")
	}
	if err = os.WriteFile(path, []byte(`{"inbounds":[{"protocol":"invalid"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if validateXrayFile(ctx, driver.Binary, driver.BinarySHA256, path) == nil {
		t.Fatal("invalid Xray config accepted")
	}
}

// Official-core syntax validation is deliberately separate from container,
// firewall and end-to-end acceptance. Unknown fields accepted by the core are
// not evidence that an address-family/security policy actually works.
func TestOfficialXrayEntryPlanValidation(t *testing.T) {
	driver := officialTestDriver(t)
	d := entryArtifact(t, "entry-example", 1)
	base := d.Entry.Credentials[0]
	protocolID := uuid.NewString()
	route := glivela.Credential{ID: "route-example", AccountID: base.Credential.AccountID, Kind: glivela.RouteCredential, User: "route-example-user", Identity: glivela.Identity(protocolID), EntryID: "entry-example", EgressID: "landing-example", Enabled: true}
	plan := d.clone().Entry
	plan.Credentials = append(plan.Credentials, glivela.CredentialMaterial{Credential: route, ProtocolID: protocolID})
	plan.Grants = []glivela.RouteGrant{{ID: "grant-example", AccountID: route.AccountID, EntryID: route.EntryID, EgressID: route.EgressID, InboundTag: plan.RealityEndpoints[0].InboundTag, Base: base.Credential, Route: route, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1}}
	plan.Peers = []glivela.RoutePeer{{EgressID: "landing-example", Address: "100.64.0.2", Port: 1080}}
	network := d.EntryNetwork.clone()
	network.Source = &landing.PeerIdentity{ID: "entry-mesh", PublicKey: "nodekey:entry", Address: "100.64.0.3"}
	network.Peers = []EntryPeer{{EgressID: "landing-example", Identity: landing.PeerIdentity{ID: "landing-mesh", PublicKey: "nodekey:landing", Address: "100.64.0.2"}, Target: "https://probe.example.test/exit", ExpectedExit: "8.8.8.8"}}
	routed, err := NewEntryDesired(*plan, network)
	if err != nil {
		t.Fatal(err)
	}
	disabledPlan := routed.clone().Entry
	for i := range disabledPlan.Credentials {
		disabledPlan.Credentials[i].Credential.Enabled = false
	}
	disabledPlan.Grants[0].Base = disabledPlan.Credentials[0].Credential
	disabledPlan.Grants[0].Route = disabledPlan.Credentials[1].Credential
	disabled, err := NewEntryDesired(*disabledPlan, network)
	if err != nil {
		t.Fatal(err)
	}
	privatePlan := routed.clone().Entry
	link := &glivela.PrivateClientLink{Source: "10.20.0.3", Address: "10.20.0.2", SourceInterface: "ens8", Interface: "ens8"}
	privatePlan.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", PublicAddress: link.Address, PrivateLink: link, ClientListenerID: "enrolled-client", Port: 24000, Key: "MDEyMzQ1Njc4OWFiY2RlZg=="}
	privatePlan.Peers[0].Port = 24000
	private, err := NewEntryDesired(*privatePlan, network)
	if err != nil {
		t.Fatal(err)
	}
	pooledPlan := d.clone().Entry
	poolRouteID := uuid.NewString()
	poolRoute := glivela.Credential{ID: "pool-route-example", AccountID: base.Credential.AccountID, Kind: glivela.RouteCredential, User: glivela.RouteUser("pool-grant-example"), Identity: glivela.Identity(poolRouteID), EntryID: "entry-example", EgressID: "landing-example", Enabled: true}
	poolGrant := glivela.RouteGrant{ID: "pool-grant-example", AccountID: poolRoute.AccountID, EntryID: poolRoute.EntryID, EgressID: poolRoute.EgressID, RelayPoolID: "pool-example", UDP: true, InboundTag: pooledPlan.RealityEndpoints[0].InboundTag, Base: base.Credential, Route: poolRoute, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1}
	pooledPlan.Credentials = append(pooledPlan.Credentials, glivela.CredentialMaterial{Credential: poolRoute, ProtocolID: poolRouteID})
	pooledPlan.Grants = []glivela.RouteGrant{poolGrant}
	obs := glivela.DefaultObservatoryConfig()
	pooledPlan.Observatory = &obs
	pooledPlan.RelayEdges = []glivela.EntryRelayEdge{
		{ID: "re-a", RelayNodeID: "relay-a", Source: "2001:4860:4860::8888", Address: "2001:4860:4860::1111", Port: glivela.RelayPoolPort, Key: "MDEyMzQ1Njc4OWFiY2RlZg==:YWJjZGVmZ2hpamtsbW5vcA=="},
		{ID: "re-b", RelayNodeID: "relay-b", Source: "2001:4860:4860::8888", Address: "2001:4860:4860::2222", Port: glivela.RelayPoolPort, Key: "MDEyMzQ1Njc4OWFiY2RlZg==:cHFyc3R1dnd4eXp7fH1+fw=="},
	}
	pooledPlan.RelayPools = []glivela.EntryRelayPool{{
		Key:       poolGrant.PoolKey(),
		GrantID:   poolGrant.ID,
		AccountID: poolGrant.AccountID,
		PoolID:    poolGrant.RelayPoolID,
		EgressID:  poolGrant.EgressID,
		UDP:       true,
		Strategy:  glivela.DefaultRelayPoolStrategy(2),
		Candidates: []glivela.EntryPoolCandidate{
			{RelayNodeID: "relay-a", RelayEdgeID: "re-a", LandingAddress: "2606:4700:4700::1111", LandingPort: glivela.RelayPoolPort, LandingKey: "MDEyMzQ1Njc4OWFiY2RlZg==:YWJjZGVmZ2hpamtsbW5vcA=="},
			{RelayNodeID: "relay-b", RelayEdgeID: "re-b", LandingAddress: "2606:4700:4700::1111", LandingPort: glivela.RelayPoolPort, LandingKey: "MDEyMzQ1Njc4OWFiY2RlZg==:cHFyc3R1dnd4eXp7fH1+fw=="},
		},
	}}
	pooledNet := EntryNetwork{
		RelayPeers: []EntryRelayNetworkPeer{
			{NodeID: "relay-a", CertificateID: strings.Repeat("a", 64), Identity: landing.PeerIdentity{ID: "relay-a-mesh", PublicKey: "nodekey:relaya", Address: "100.64.0.11"}},
			{NodeID: "relay-b", CertificateID: strings.Repeat("b", 64), Identity: landing.PeerIdentity{ID: "relay-b-mesh", PublicKey: "nodekey:relayb", Address: "100.64.0.12"}},
		},
		PooledLandings: []EntryPooledLanding{{
			EgressID:      "landing-example",
			CertificateID: strings.Repeat("c", 64),
			Identity:      &landing.PeerIdentity{ID: "landing-mesh", PublicKey: "nodekey:landing", Address: "100.64.0.2"},
			ExpectedExit:  "8.8.8.8",
		}},
	}
	pooled, err := NewEntryDesired(*pooledPlan, pooledNet)
	if err != nil {
		t.Fatal(err)
	}
	emptyPoolPlan := pooled.clone().Entry
	emptyPoolPlan.RelayEdges = nil
	emptyPoolPlan.RelayPools[0].Candidates = nil
	emptyPoolNet := EntryNetwork{
		PooledLandings: pooledNet.PooledLandings,
	}
	emptyPool, err := NewEntryDesired(*emptyPoolPlan, emptyPoolNet)
	if err != nil {
		t.Fatal(err)
	}
	// Empty authentication inventories must at least validate with the pinned
	// original core. This is syntax evidence, not actual authentication denial.
	for _, desired := range []Desired{d, routed, disabled, private, pooled, emptyPool} {
		path := filepath.Join(t.TempDir(), "entry.json")
		if err := os.WriteFile(path, desired.Config, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := validateXrayFile(ctx, driver.Binary, driver.BinarySHA256, path)
		cancel()
		if err != nil {
			t.Fatal("entry plan was rejected by the packaged official core", err)
		}
	}
}
