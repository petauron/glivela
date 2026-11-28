//go:build linux

package landing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

const (
	relayPoolTestPayloadBytes = 16384
	relayPoolUserTrafficMin   = 16384
	relayPoolProbeNoiseMax    = 2048
	relayPoolDocTargetCIDR    = "198.51.100.34/32"
	relayPoolMaxRTTMS         = 120
	relayPoolMaxTolerance     = 0.25
)

type relayPoolTopologyAFixture struct {
	xrayBin       string
	probeSrv      *controllableProbeServer
	tcpObs        *observedSources
	udpObs        *observedSources
	udp443Obs     *observedSources
	privUDPObs    *observedSources
	privTCPObs    *observedSources
	beforePrivTCP int
	proxyA        *controllableRelayProxy
	proxyB        *controllableRelayProxy
}

func startRelayPoolTopologyA(t *testing.T, ctx context.Context, holdInitialProbe bool) *relayPoolTopologyAFixture {
	t.Helper()
	core := requireRelayPoolNamespace(t)

	setupRelayPoolLoopback(t, ctx,
		[]string{
			"192.0.2.99/32",    // entry decoy direct exit (must never appear)
			"198.51.100.34/32", // synthetic documentation probe/TCP/UDP target
			"203.0.113.51/32",  // fixed landing-1 IPv4 exit
			"192.168.50.3/32",  // forbidden RFC1918 private destination
		},
		[]string{
			"2001:db8:240::10/128",  // entry IPv6
			"2001:db8:240::21/128",  // relay-a IPv6
			"2001:db8:240::22/128",  // relay-b IPv6
			"2001:db8:240::31/128",  // landing-1 IPv6
			"2001:db8:240::121/128", // fault-injection proxy for relay-a
			"2001:db8:240::122/128", // fault-injection proxy for relay-b
		},
	)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	xrayBin := filepath.Join(dir, "xray")
	udpRuntimeCopyExecutable(t, core, xrayBin)

	// Start active witness servers for every positive and negative target and
	// prove negative witnesses answer directly so denials are never unbound ports.
	probeSrv := startControllableProbeServer(t, "198.51.100.34:8080")
	tcpObs := startSourceEchoTCPServer(t, "198.51.100.34:8444")
	udpObs := startSourceEchoUDPServer(t, "198.51.100.34:8443")
	udp443Obs := startSourceEchoUDPServer(t, "198.51.100.34:443")
	privUDPObs := startSourceEchoUDPServer(t, "192.168.50.3:8443")
	privTCPObs := startSourceEchoTCPServer(t, "192.168.50.3:8444")

	verifyUDPWitnessReachable(t, "198.51.100.34:443", "192.0.2.99")
	verifyUDPWitnessReachable(t, "192.168.50.3:8443", "192.0.2.99")
	verifyTCPWitnessReachable(t, "192.168.50.3:8444", "192.0.2.99")

	// Independent 16-byte SS2022 EIH keys (server iPSK + per-edge uPSK).
	const (
		relayAIPSK    = "AAECAwQFBgcICQoLDA0ODw=="
		relayAUPSK    = "EBESExQVFhcYGRobHB0eHw=="
		relayBIPSK    = "ICEiIyQlJicoKSorLC0uLw=="
		relayBUPSK    = "MDEyMzQ1Njc4OTo7PD0+Pw=="
		landing1IPSK  = "QEFCQ0RFRkdISUpLTE1OTw=="
		landing1UPSKA = "UFFSU1RVVldYWVpbXF1eXw=="
		landing1UPSKB = "YGFhYmNkZWZnaGlqa2xtbg=="
	)

	landing1Cfg := buildEIHLandingConfig(eihLandingSpec{
		apiPort:       19093,
		listenIPv6:    "2001:db8:240::31",
		serverIPSK:    landing1IPSK,
		defaultEgress: "203.0.113.51",
		clients: []eihRouteClient{
			{email: "relay-a", upsk: landing1UPSKA, sourceCIDR: "2001:db8:240::21/128", allowUDP: true},
			{email: "relay-b", upsk: landing1UPSKB, sourceCIDR: "2001:db8:240::22/128", allowUDP: true},
		},
	})
	_ = startManagedXray(t, ctx, xrayBin, dir, "landing-1",
		[]string{"127.0.0.1:19093", "[2001:db8:240::31]:24000"}, landing1Cfg)

	relayACfg := buildEIHRelayOnlyConfig(19091, "2001:db8:240::21", relayAIPSK,
		[]eihRelayUser{{email: "entry-to-relay-a", upsk: relayAUPSK, sourceCIDR: "2001:db8:240::10/128"}},
		[]string{"2001:db8:240::31/128"},
	)
	relayBCfg := buildEIHRelayOnlyConfig(19092, "2001:db8:240::22", relayBIPSK,
		[]eihRelayUser{{email: "entry-to-relay-b", upsk: relayBUPSK, sourceCIDR: "2001:db8:240::10/128"}},
		[]string{"2001:db8:240::31/128"},
	)
	_ = startManagedXray(t, ctx, xrayBin, dir, "relay-a",
		[]string{"127.0.0.1:19091", "[2001:db8:240::21]:24000"}, relayACfg)
	_ = startManagedXray(t, ctx, xrayBin, dir, "relay-b",
		[]string{"127.0.0.1:19092", "[2001:db8:240::22]:24000"}, relayBCfg)

	proxyA := newControllableRelayProxy(t, "[2001:db8:240::121]:24000", "[2001:db8:240::21]:24000", "2001:db8:240::10")
	proxyB := newControllableRelayProxy(t, "[2001:db8:240::122]:24000", "[2001:db8:240::22]:24000", "2001:db8:240::10")
	proxyA.StartListener(t)
	proxyB.StartListener(t)

	assertNoUDPPort24000(t, ctx)

	if holdInitialProbe {
		probeSrv.SetHold(true)
	}
	entryCfg := buildRelayPoolEntryConfig(entryPoolSpec{
		apiPort:       19085,
		socksPort:     19180,
		emptyPoolPort: 19181,
		entryIPv6:     "2001:db8:240::10",
		decoyDirectV4: "192.0.2.99",
		probeURL:      "http://198.51.100.34:8080/generate_204",
		maxRTT:        "120ms",
		relays: []entryRelaySpec{
			{tag: "relay-a", addr: "2001:db8:240::121", password: relayAIPSK + ":" + relayAUPSK},
			{tag: "relay-b", addr: "2001:db8:240::122", password: relayBIPSK + ":" + relayBUPSK},
		},
		candidates: []entryCandidateSpec{
			{tag: "route-l1-r0", relayTag: "relay-a", landingAddr: "2001:db8:240::31", landingPassword: landing1IPSK + ":" + landing1UPSKA, udp: true},
			{tag: "route-l1-r1", relayTag: "relay-b", landingAddr: "2001:db8:240::31", landingPassword: landing1IPSK + ":" + landing1UPSKB, udp: true},
		},
		expected:    2,
		fallbackTag: "route-l1-r0",
	})
	_ = startManagedXray(t, ctx, xrayBin, dir, "entry-main",
		[]string{"127.0.0.1:19085", "127.0.0.1:19180", "127.0.0.1:19181"}, entryCfg)

	return &relayPoolTopologyAFixture{
		xrayBin:       xrayBin,
		probeSrv:      probeSrv,
		tcpObs:        tcpObs,
		udpObs:        udpObs,
		udp443Obs:     udp443Obs,
		privUDPObs:    privUDPObs,
		privTCPObs:    privTCPObs,
		beforePrivTCP: privTCPObs.total(),
		proxyA:        proxyA,
		proxyB:        proxyB,
	}
}

// TestOfficialCoreRelayPoolFailover verifies Phase 0 Topology A cold-start,
// empty-pool blocking, healthy leastLoad spreading, and live hard-failure
// (connection-refused and hang/timeout) TCP & XUDP recovery and rejoin on the
// pinned official Xray 26.11.9 core inside an isolated Linux netns.
func TestOfficialCoreRelayPoolFailover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Second)
	defer cancel()

	fx := startRelayPoolTopologyA(t, ctx, true)

	// Sub-case 1: Cold-start (gate initial probe) + empty authorized pool -> blocked.
	time.Sleep(300 * time.Millisecond)
	coldStatus, err := queryObservatoryStatus(ctx, "127.0.0.1:19085")
	if err != nil {
		t.Fatalf("cold-start ObservatoryService query failed: %v", err)
	}
	if coldStatus["route-l1-r0"].Alive || coldStatus["route-l1-r1"].Alive {
		t.Fatalf("expected no completed alive probes during cold-start hold, got %+v", coldStatus)
	}

	// Cold-start TCP request MUST succeed via fallbackTag (route-l1-r0 -> relay-a -> landing-1).
	beforeA, beforeB := queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", relayPoolTestPayloadBytes); err != nil {
		t.Fatalf("cold-start fallback TCP failed: %v", err)
	}
	afterA, afterB := queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if afterA-beforeA < relayPoolUserTrafficMin || afterB-beforeB >= relayPoolProbeNoiseMax {
		t.Fatalf("cold-start did not use fallbackTag r0 exclusively: deltaA=%d deltaB=%d", afterA-beforeA, afterB-beforeB)
	}

	// Release probe hold promptly; wait until BOTH candidates satisfy the exact
	// leastLoad eligibility predicate (Alive, DelayMS < maxRTT, Fail/All <= tolerance).
	fx.probeSrv.SetHold(false)

	// Empty authorized pool MUST explicitly route to blocked (never leak to decoy direct).
	if err := assertSOCKS5TCPEcho("127.0.0.1:19181", "198.51.100.34:8444", "203.0.113.51", 64); err == nil {
		t.Fatal("empty authorized pool unexpectedly reached TCP target")
	}
	assertSOCKS5UDPDenied(t, "127.0.0.1:19181", "198.51.100.34:8443", fx.udpObs)
	assertNoDecoyDirectHits(t, fx.tcpObs, fx.udpObs, "192.0.2.99")

	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "both candidates leastLoad-eligible", func(m map[string]observatoryOutboundStatus) bool {
		return candidateEligible(m["route-l1-r0"], relayPoolMaxRTTMS, relayPoolMaxTolerance) &&
			candidateEligible(m["route-l1-r1"], relayPoolMaxRTTMS, relayPoolMaxTolerance)
	})

	// Sub-case 2: Healthy leastLoad (expected=2) spreads traffic across BOTH relays,
	// with real XUDP round-trips and fixed exit IP 203.0.113.51.
	beforeA, beforeB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	for i := 0; i < 24; i++ {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", relayPoolTestPayloadBytes); err != nil {
			t.Fatalf("healthy TCP request %d failed: %v", i, err)
		}
	}
	afterA, afterB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if afterA-beforeA < relayPoolUserTrafficMin || afterB-beforeB < relayPoolUserTrafficMin {
		t.Fatalf("expected leastLoad(expected=2) to spread traffic across both relays, got deltaA=%d deltaB=%d", afterA-beforeA, afterB-beforeB)
	}
	for _, size := range []int{64, 512, 1200} {
		if err := assertSOCKS5UDPEcho("127.0.0.1:19180", "198.51.100.34:8443", "203.0.113.51", size); err != nil {
			t.Fatalf("healthy XUDP size=%d failed: %v", size, err)
		}
	}
	assertSOCKS5UDPDenied(t, "127.0.0.1:19180", "198.51.100.34:443", fx.udp443Obs)
	assertSOCKS5UDPDenied(t, "127.0.0.1:19180", "192.168.50.3:8443", fx.privUDPObs)
	if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "192.168.50.3:8444", "203.0.113.51", 64); err == nil {
		t.Fatal("private TCP destination unexpectedly reached")
	}
	if fx.privTCPObs.total() != fx.beforePrivTCP {
		t.Fatalf("private TCP target observed unauthorized connections: before=%d after=%d", fx.beforePrivTCP, fx.privTCPObs.total())
	}

	// Sub-case 3a: Live hard failure (connection refused) on running entry ->
	// continuously probe new TCP & XUDP connections to measure true business recovery,
	// verify 100% traffic shifts to relay-b, then rejoin relay-a.
	faultAt := time.Now()
	fx.proxyA.StopListener()
	refusedMetrics := measureHardFaultRecovery(t, ctx, "127.0.0.1:19180", "127.0.0.1:19085", "198.51.100.34:8444", "198.51.100.34:8443", "203.0.113.51", faultAt, 35*time.Second)
	t.Logf("measured connection-refused new-connection recovery: tcp=%s xudp=%s evicted=%s tcp_fails=%d xudp_fails=%d",
		refusedMetrics.tcpRecoveredAt.Round(time.Millisecond),
		refusedMetrics.xudpRecoveredAt.Round(time.Millisecond),
		refusedMetrics.evictedAt.Round(time.Millisecond),
		refusedMetrics.tcpFailures,
		refusedMetrics.xudpFailures)

	beforeA, beforeB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	for i := 0; i < 8; i++ {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", relayPoolTestPayloadBytes); err != nil {
			t.Fatalf("post-refused TCP %d failed: %v", i, err)
		}
	}
	afterA, afterB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if afterA-beforeA != 0 || afterB-beforeB < 8*relayPoolUserTrafficMin {
		t.Fatalf("expected 100%% post-refused traffic on relay-b, got deltaA=%d deltaB=%d", afterA-beforeA, afterB-beforeB)
	}

	rejoinStart := time.Now()
	fx.proxyA.StartListener(t)
	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "route-l1-r0 rejoined after connection-refused", func(m map[string]observatoryOutboundStatus) bool {
		return candidateEligible(m["route-l1-r0"], relayPoolMaxRTTMS, relayPoolMaxTolerance) &&
			candidateEligible(m["route-l1-r1"], relayPoolMaxRTTMS, relayPoolMaxTolerance)
	})
	t.Logf("measured auto-rejoin time after connection-refused: %s", time.Since(rejoinStart).Round(time.Millisecond))

	beforeA, beforeB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	for i := 0; i < 24; i++ {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", relayPoolTestPayloadBytes); err != nil {
			t.Fatalf("post-rejoin TCP %d failed: %v", i, err)
		}
	}
	afterA, afterB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if afterA-beforeA < relayPoolUserTrafficMin || afterB-beforeB < relayPoolUserTrafficMin {
		t.Fatalf("expected traffic spreading after relay-a rejoin, got deltaA=%d deltaB=%d", afterA-beforeA, afterB-beforeB)
	}

	// Sub-case 3b: Live hard failure (hang / connection timeout blackhole) on same
	// running entry -> continuously measure TCP & XUDP recovery -> rejoin.
	faultAt = time.Now()
	fx.proxyA.SetMode(relayProxyBlackhole)
	timeoutMetrics := measureHardFaultRecovery(t, ctx, "127.0.0.1:19180", "127.0.0.1:19085", "198.51.100.34:8444", "198.51.100.34:8443", "203.0.113.51", faultAt, 35*time.Second)
	t.Logf("measured hang-timeout new-connection recovery: tcp=%s xudp=%s evicted=%s tcp_fails=%d xudp_fails=%d",
		timeoutMetrics.tcpRecoveredAt.Round(time.Millisecond),
		timeoutMetrics.xudpRecoveredAt.Round(time.Millisecond),
		timeoutMetrics.evictedAt.Round(time.Millisecond),
		timeoutMetrics.tcpFailures,
		timeoutMetrics.xudpFailures)

	fx.proxyA.SetMode(relayProxyPass)
	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "route-l1-r0 rejoined after hang-timeout", func(m map[string]observatoryOutboundStatus) bool {
		return candidateEligible(m["route-l1-r0"], relayPoolMaxRTTMS, relayPoolMaxTolerance) &&
			candidateEligible(m["route-l1-r1"], relayPoolMaxRTTMS, relayPoolMaxTolerance)
	})
	assertNoDecoyDirectHits(t, fx.tcpObs, fx.udpObs, "192.0.2.99")
}

// TestOfficialCoreRelayPoolDegradedAndOutage runs in its own isolated netns in
// parallel with TestOfficialCoreRelayPoolFailover so each probe-jitter budget
// stays bounded. It validates:
//   - live gray-failure latency crossing maxRTT on a running entry + recovery
//   - external 204 probe target outage fallback to r0 with zero blackout
//   - all-relays-down fallback ONLY AFTER both candidates exit qualified pool,
//     proving r0 receives fallback attempts while r1 and decoy direct receive none
func TestOfficialCoreRelayPoolDegradedAndOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Second)
	defer cancel()

	fx := startRelayPoolTopologyA(t, ctx, false)

	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "both candidates initially leastLoad-eligible", func(m map[string]observatoryOutboundStatus) bool {
		return candidateEligible(m["route-l1-r0"], relayPoolMaxRTTMS, relayPoolMaxTolerance) &&
			candidateEligible(m["route-l1-r1"], relayPoolMaxRTTMS, relayPoolMaxTolerance)
	})

	// Sub-case 1: Live gray-failure injection on the SAME running entry:
	// relay-a transitions from ~1ms healthy RTT to 250ms (> maxRTT=120ms).
	faultAt := time.Now()
	fx.proxyA.SetDelay(250 * time.Millisecond)
	grayMetrics := measureLatencyEvictionRecovery(t, ctx, "127.0.0.1:19180", "127.0.0.1:19085", "198.51.100.34:8444", "198.51.100.34:8443", "203.0.113.51", faultAt, 35*time.Second)
	t.Logf("measured live maxRTT gray-failure recovery: tcp_fast=%s xudp_fast=%s observed_above_maxrtt=%s slow_tcp_hits=%d",
		grayMetrics.tcpRecoveredAt.Round(time.Millisecond),
		grayMetrics.xudpRecoveredAt.Round(time.Millisecond),
		grayMetrics.evictedAt.Round(time.Millisecond),
		grayMetrics.tcpFailures)

	beforeA, beforeB := queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	for i := 0; i < 12; i++ {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", relayPoolTestPayloadBytes); err != nil {
			t.Fatalf("post-maxRTT TCP %d failed: %v", i, err)
		}
	}
	afterA, afterB := queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if afterA-beforeA >= relayPoolProbeNoiseMax || afterB-beforeB < 12*relayPoolUserTrafficMin {
		t.Fatalf("live maxRTT did not evict slow relay-a: deltaA=%d deltaB=%d", afterA-beforeA, afterB-beforeB)
	}
	fx.proxyA.SetDelay(0)
	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "route-l1-r0 latency recovered below maxRTT", func(m map[string]observatoryOutboundStatus) bool {
		return candidateEligible(m["route-l1-r0"], relayPoolMaxRTTMS, relayPoolMaxTolerance) &&
			candidateEligible(m["route-l1-r1"], relayPoolMaxRTTMS, relayPoolMaxTolerance)
	})

	// Sub-case 2: External 204 probe target outage while data path is healthy ->
	// fallbackTag r0 keeps traffic flowing to fixed exit 203.0.113.51 with zero blackout.
	fx.probeSrv.SetDrop(true)
	defer fx.probeSrv.SetDrop(false)
	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "all probes marked unhealthy during 204 outage", func(m map[string]observatoryOutboundStatus) bool {
		r0, ok0 := m["route-l1-r0"]
		r1, ok1 := m["route-l1-r1"]
		return ok0 && ok1 && !r0.Alive && !r1.Alive
	})
	beforeA, beforeB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	for i := 0; i < 4; i++ {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", relayPoolTestPayloadBytes); err != nil {
			t.Fatalf("204-outage fallback TCP %d failed: %v", i, err)
		}
	}
	if err := assertSOCKS5UDPEcho("127.0.0.1:19180", "198.51.100.34:8443", "203.0.113.51", 512); err != nil {
		t.Fatalf("204-outage fallback XUDP failed: %v", err)
	}
	afterA, afterB = queryLandingRelayUplink(t, ctx, fx.xrayBin, "127.0.0.1:19093")
	if afterA-beforeA < 4*relayPoolUserTrafficMin || afterB-beforeB >= relayPoolProbeNoiseMax {
		t.Fatalf("expected 204-outage traffic exclusively on fallbackTag r0, got deltaA=%d deltaB=%d", afterA-beforeA, afterB-beforeB)
	}
	fx.probeSrv.SetDrop(false)
	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "both candidates healthy after 204 recovery", func(m map[string]observatoryOutboundStatus) bool {
		return candidateEligible(m["route-l1-r0"], relayPoolMaxRTTMS, relayPoolMaxTolerance) &&
			candidateEligible(m["route-l1-r1"], relayPoolMaxRTTMS, relayPoolMaxTolerance)
	})

	// Sub-case 3: All relays unreachable AFTER both candidates exit qualified pool ->
	// verify balancing.go falls back exclusively to fallbackTag r0 (counted on proxyA),
	// never routes data traffic to r1 (proxyB) and never leaks to decoy-direct.
	fx.proxyA.SetMode(relayProxyReset)
	fx.proxyB.SetMode(relayProxyReset)
	waitObservatoryCondition(t, ctx, "127.0.0.1:19085", 30*time.Second, "both candidates evicted after all-relays-down", func(m map[string]observatoryOutboundStatus) bool {
		r0, ok0 := m["route-l1-r0"]
		r1, ok1 := m["route-l1-r1"]
		return ok0 && ok1 && !r0.Alive && !r1.Alive
	})
	attemptsBeforeA, attemptsBeforeB := fx.proxyA.Attempts(), fx.proxyB.Attempts()
	for i := 0; i < 10; i++ {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19180", "198.51.100.34:8444", "203.0.113.51", 64); err == nil {
			t.Fatalf("all-relays-down TCP %d unexpectedly succeeded", i)
		}
	}
	deltaAttemptsA := fx.proxyA.Attempts() - attemptsBeforeA
	deltaAttemptsB := fx.proxyB.Attempts() - attemptsBeforeB
	if deltaAttemptsA < 10 || deltaAttemptsB > 2 {
		t.Fatalf("all-relays-down did not fall back exclusively to r0: attemptsA=%d attemptsB=%d", deltaAttemptsA, deltaAttemptsB)
	}
	assertSOCKS5UDPDenied(t, "127.0.0.1:19180", "198.51.100.34:8443", fx.udpObs)
	assertNoDecoyDirectHits(t, fx.tcpObs, fx.udpObs, "192.0.2.99")
	if fx.privTCPObs.total() != fx.beforePrivTCP {
		t.Fatalf("private TCP target unexpectedly hit: before=%d after=%d", fx.beforePrivTCP, fx.privTCPObs.total())
	}
}

// TestOfficialCoreSinglePortEIHAndIsolation verifies Phase 0 Topology B on the
// pinned official Xray 26.11.9 core inside an isolated loopback-only Linux netns:
// 1 entry -> 1 dual-role single-port 24000 EIH node -> 2 fixed 24000 EIH landings.
//
// It validates:
//   - single port 24000 EIH multi-user isolating fixed-landing vs relay roles
//     and IPv4 vs IPv6 ingress via inboundTag + user + source
//   - per-landing TCP vs TCP+XUDP isolation on a shared (entry -> relay:24000) edge
//   - defense-in-depth UDP 443 denial at the landing layer (entry allows UDP 443)
//   - relay Xray policy layer rejecting inner XUDP tunneled over TCP 24000
//   - direct freedom.finalRules destination whitelist with same-family IPv6
//     controls (public, ULA private, wrong port, wrong IP) and per-credential
//     downstream landing isolation (v4 relay allowed ONLY to landing-1, denied
//     to live landing-2)
//   - strict rejection of wrong source IP, unknown uPSK, and genuine before/after
//     EIH clients[] key revocation (routing rule retained) without affecting
//     retained credentials
//   - per-full-path health isolation in ObservatoryService when landing-2 fails
func TestOfficialCoreSinglePortEIHAndIsolation(t *testing.T) {
	core := requireRelayPoolNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 105*time.Second)
	defer cancel()

	setupRelayPoolLoopback(t, ctx,
		[]string{
			"192.0.2.10/32",    // entry IPv4 ingress source
			"198.51.100.21/32", // relay-dual IPv4 24000 listener
			"198.51.100.34/32", // synthetic documentation probe/TCP/UDP target
			"203.0.113.21/32",  // relay-dual fixed IPv4 landing exit
			"203.0.113.51/32",  // landing-1 primary fixed IPv4 exit
			"203.0.113.52/32",  // landing-2 fixed IPv4 exit
			"203.0.113.53/32",  // landing-1 secondary fixed IPv4 exit (same landing, distinct EIH uPSK)
			"192.168.50.3/32",  // forbidden RFC1918 private destination
		},
		[]string{
			"2001:db8:240::10/128", // entry authorized IPv6 source
			"2001:db8:240::99/128", // unauthorized IPv6 source & unauthorized IPv6:24000 target
			"2001:db8:240::21/128", // relay-dual IPv6 24000 listener & relay egress
			"2001:db8:240::31/128", // landing-1 IPv6 24000 listener
			"2001:db8:240::32/128", // landing-2 IPv6 24000 listener
			"2001:db8:240::34/128", // unauthorized same-family IPv6 target (:8444 & :8443)
			"fd00:240::3/128",      // forbidden private ULA IPv6 target (:24000)
		},
	)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	xrayBin := filepath.Join(dir, "xray")
	udpRuntimeCopyExecutable(t, core, xrayBin)

	_ = startControllableProbeServer(t, "198.51.100.34:8080")
	tcpObs := startSourceEchoTCPServer(t, "198.51.100.34:8444")
	udpObs := startSourceEchoUDPServer(t, "198.51.100.34:8443")
	udp443Obs := startSourceEchoUDPServer(t, "198.51.100.34:443")
	privUDPObs := startSourceEchoUDPServer(t, "192.168.50.3:8443")
	privTCPObs := startSourceEchoTCPServer(t, "192.168.50.3:8444")
	v6PubTCPObs := startSourceEchoTCPServer(t, "[2001:db8:240::34]:8444")
	v6PrivTCPObs := startSourceEchoTCPServer(t, "[fd00:240::3]:24000")
	wrongPortTCPObs := startSourceEchoTCPServer(t, "[2001:db8:240::31]:24001")
	wrongIP24000Obs := startSourceEchoTCPServer(t, "[2001:db8:240::99]:24000")
	v6UDPObs := startSourceEchoUDPServer(t, "[2001:db8:240::34]:8443")

	// Prove every negative-control witness is live and directly reachable.
	verifyUDPWitnessReachable(t, "198.51.100.34:443", "192.0.2.10")
	verifyUDPWitnessReachable(t, "192.168.50.3:8443", "192.0.2.10")
	verifyUDPWitnessReachable(t, "[2001:db8:240::34]:8443", "2001:db8:240::10")
	verifyTCPWitnessReachable(t, "192.168.50.3:8444", "192.0.2.10")
	verifyTCPWitnessReachable(t, "[2001:db8:240::34]:8444", "2001:db8:240::10")
	verifyTCPWitnessReachable(t, "[fd00:240::3]:24000", "2001:db8:240::10")
	verifyTCPWitnessReachable(t, "[2001:db8:240::31]:24001", "2001:db8:240::10")
	verifyTCPWitnessReachable(t, "[2001:db8:240::99]:24000", "2001:db8:240::10")

	const (
		relayDualIPSK   = "AAECAwQFBgcICQoLDA0ODw=="
		upskV6Landing   = "EBESExQVFhcYGRobHB0eHw=="
		upskV6Relay     = "ICEiIyQlJicoKSorLC0uLw=="
		upskV4Relay     = "MDEyMzQ1Njc4OTo7PD0+Pw=="
		upskTempRelay   = "Q0RFRkdISUpLTE1OT1BRUg=="
		upskUnknown     = "f359fHx7enl4d3Z1dHNycQ=="
		landing1IPSK    = "QEFCQ0RFRkdISUpLTE1OTw=="
		landing1UPSK    = "UFFSU1RVVldYWVpbXF1eXw=="
		landing1AltUPSK = "YWJjZGVmZ2hpamtsbW5vcA=="
		landing2IPSK    = "YGFhYmNkZWZnaGlqa2xtbg=="
		landing2UPSK    = "b3BxcnN0dXZ3eHl6e3x9fg=="
	)

	landing1 := startManagedXray(t, ctx, xrayBin, dir, "landing-1",
		[]string{"127.0.0.1:19191", "[2001:db8:240::31]:24000"},
		buildEIHLandingConfig(eihLandingSpec{
			apiPort:       19191,
			listenIPv6:    "2001:db8:240::31",
			serverIPSK:    landing1IPSK,
			defaultEgress: "203.0.113.51",
			clients: []eihRouteClient{
				{email: "relay-dual-l1", upsk: landing1UPSK, sourceCIDR: "2001:db8:240::21/128", allowUDP: true},
				{email: "relay-dual-l1-alt", upsk: landing1AltUPSK, sourceCIDR: "2001:db8:240::21/128", allowUDP: true, egressIP: "203.0.113.53"},
			},
		}))
	defer landing1.Stop()

	landing2 := startManagedXray(t, ctx, xrayBin, dir, "landing-2",
		[]string{"127.0.0.1:19192", "[2001:db8:240::32]:24000"},
		buildEIHLandingConfig(eihLandingSpec{
			apiPort:       19192,
			listenIPv6:    "2001:db8:240::32",
			serverIPSK:    landing2IPSK,
			defaultEgress: "203.0.113.52",
			clients:       []eihRouteClient{{email: "relay-dual-l2", upsk: landing2UPSK, sourceCIDR: "2001:db8:240::21/128", allowUDP: false}},
		}))
	defer landing2.Stop()

	// Dual-role node listening ONLY on port 24000 (IPv6 + IPv4) serving:
	//   1) entry-v6-landing    -> fixed IPv4 egress 203.0.113.21 (TCP+XUDP, deny private & UDP443)
	//   2) entry-v6-relay      -> relay-egress-v6: ONLY ::31:24000 & ::32:24000/TCP
	//   3) entry-v6-temp-relay -> relay-egress-v6 (initially in clients[], then removed while rule stays)
	//   4) entry-v4-relay      -> relay-egress-v4-l1-only: ONLY ::31:24000/TCP (NOT ::32!)
	relayDualSpec := dualRoleSpec{
		apiPort:             19190,
		listenIPv6:          "2001:db8:240::21",
		listenIPv4:          "198.51.100.21",
		serverIPSK:          relayDualIPSK,
		landingEgressV4:     "203.0.113.21",
		upskV6Landing:       upskV6Landing,
		upskV6Relay:         upskV6Relay,
		upskTempRelay:       upskTempRelay,
		upskV4Relay:         upskV4Relay,
		entryV6CIDR:         "2001:db8:240::10/128",
		entryV4CIDR:         "192.0.2.10/32",
		v6AllowedLandings:   []string{"2001:db8:240::31/128", "2001:db8:240::32/128"},
		v4AllowedLandings:   []string{"2001:db8:240::31/128"},
		includeTempRelayKey: true,
	}
	relayDual := startManagedXray(t, ctx, xrayBin, dir, "relay-dual",
		[]string{"127.0.0.1:19190", "[2001:db8:240::21]:24000", "198.51.100.21:24000"},
		buildDualRoleSinglePort24000Config(relayDualSpec))
	defer relayDual.Stop()

	assertNoUDPPort24000(t, ctx)

	entryCfg := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"api": map[string]any{"tag": "api", "listen": "127.0.0.1:19086", "services": []string{"ObservatoryService"}},
		"burstObservatory": map[string]any{
			"subjectSelector": []string{"path-"},
			"pingConfig": map[string]any{
				"destination": "http://198.51.100.34:8080/generate_204",
				"interval":    "10s",
				"sampling":    1,
				"timeout":     "1s",
			},
		},
		"inbounds": []any{
			socksTestInbound("in-hk-landing", 19280),
			socksTestInbound("in-l1", 19281),
			socksTestInbound("in-l2", 19282),
			socksTestInbound("in-l1-v4", 19283),
			socksTestInbound("in-abuse-relay", 19284),
			socksTestInbound("in-wrong-source", 19285),
			socksTestInbound("in-unknown-upsk", 19286),
			socksTestInbound("in-abuse-relay-xudp", 19287),
			socksTestInbound("in-temp-upsk", 19288),
			socksTestInbound("in-hk-landing-allow443", 19289),
			socksTestInbound("in-l2-v4-denied", 19290),
			socksTestInbound("in-no-sendthrough", 19291),
			socksTestInbound("in-l1-alt", 19292),
		},
		"outbounds": []any{
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
			ss2022ClientOutbound("twohop-hk-landing", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskV6Landing, "2001:db8:240::10", "", true, "reject"),
			ss2022ClientOutbound("twohop-hk-landing-allow443", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskV6Landing, "2001:db8:240::10", "", true, "allow"),
			ss2022ClientOutbound("relay-v6", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskV6Relay, "2001:db8:240::10", "", false, ""),
			ss2022ClientOutbound("relay-v6-xudp", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskV6Relay, "2001:db8:240::10", "", true, "allow"),
			ss2022ClientOutbound("relay-v4", "198.51.100.21", 24000, relayDualIPSK+":"+upskV4Relay, "192.0.2.10", "", false, ""),
			ss2022ClientOutbound("path-l1", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1UPSK, "", "relay-v6", true, "reject"),
			ss2022ClientOutbound("path-l1-alt", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1AltUPSK, "", "relay-v6", true, "reject"),
			ss2022ClientOutbound("path-l2", "2001:db8:240::32", 24000, landing2IPSK+":"+landing2UPSK, "", "relay-v6", true, "reject"),
			ss2022ClientOutbound("v4-l1", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1UPSK, "", "relay-v4", false, ""),
			ss2022ClientOutbound("v4-l2", "2001:db8:240::32", 24000, landing2IPSK+":"+landing2UPSK, "", "relay-v4", false, ""),
			ss2022ClientOutbound("wrong-source-relay", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskV6Relay, "2001:db8:240::99", "", false, ""),
			ss2022ClientOutbound("wrong-source-path", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1UPSK, "", "wrong-source-relay", false, ""),
			ss2022ClientOutbound("no-sendthrough-relay", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskV6Relay, "", "", false, ""),
			ss2022ClientOutbound("no-sendthrough-path", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1UPSK, "", "no-sendthrough-relay", false, ""),
			ss2022ClientOutbound("unknown-upsk-relay", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskUnknown, "2001:db8:240::10", "", false, ""),
			ss2022ClientOutbound("unknown-upsk-path", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1UPSK, "", "unknown-upsk-relay", false, ""),
			ss2022ClientOutbound("temp-upsk-relay", "2001:db8:240::21", 24000, relayDualIPSK+":"+upskTempRelay, "2001:db8:240::10", "", false, ""),
			ss2022ClientOutbound("temp-upsk-path", "2001:db8:240::31", 24000, landing1IPSK+":"+landing1UPSK, "", "temp-upsk-relay", false, ""),
		},
		"routing": map[string]any{
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []string{"in-hk-landing"}, "outboundTag": "twohop-hk-landing"},
				map[string]any{"type": "field", "inboundTag": []string{"in-hk-landing-allow443"}, "outboundTag": "twohop-hk-landing-allow443"},
				map[string]any{"type": "field", "inboundTag": []string{"in-l1"}, "outboundTag": "path-l1"},
				map[string]any{"type": "field", "inboundTag": []string{"in-l1-alt"}, "outboundTag": "path-l1-alt"},
				map[string]any{"type": "field", "inboundTag": []string{"in-l2"}, "outboundTag": "path-l2"},
				map[string]any{"type": "field", "inboundTag": []string{"in-l1-v4"}, "outboundTag": "v4-l1"},
				map[string]any{"type": "field", "inboundTag": []string{"in-l2-v4-denied"}, "outboundTag": "v4-l2"},
				map[string]any{"type": "field", "inboundTag": []string{"in-abuse-relay"}, "outboundTag": "relay-v6"},
				map[string]any{"type": "field", "inboundTag": []string{"in-abuse-relay-xudp"}, "outboundTag": "relay-v6-xudp"},
				map[string]any{"type": "field", "inboundTag": []string{"in-wrong-source"}, "outboundTag": "wrong-source-path"},
				map[string]any{"type": "field", "inboundTag": []string{"in-no-sendthrough"}, "outboundTag": "no-sendthrough-path"},
				map[string]any{"type": "field", "inboundTag": []string{"in-unknown-upsk"}, "outboundTag": "unknown-upsk-path"},
				map[string]any{"type": "field", "inboundTag": []string{"in-temp-upsk"}, "outboundTag": "temp-upsk-path"},
			},
		},
	}
	entryReady := []string{"127.0.0.1:19086"}
	for p := 19280; p <= 19292; p++ {
		entryReady = append(entryReady, fmt.Sprintf("127.0.0.1:%d", p))
	}
	entry := startManagedXray(t, ctx, xrayBin, dir, "entry-isolation", entryReady, entryCfg)
	defer entry.Stop()

	// 1. Single-port 24000 dual-role & dual-stack functional verification.
	if err := assertSOCKS5TCPEcho("127.0.0.1:19280", "198.51.100.34:8444", "203.0.113.21", 256); err != nil {
		t.Fatalf("dual-role fixed landing TCP failed: %v", err)
	}
	if err := assertSOCKS5UDPEcho("127.0.0.1:19280", "198.51.100.34:8443", "203.0.113.21", 256); err != nil {
		t.Fatalf("dual-role fixed landing XUDP failed: %v", err)
	}
	// Entry-side xudpProxyUDP443:reject blocks UDP 443.
	assertSOCKS5UDPDenied(t, "127.0.0.1:19280", "198.51.100.34:443", udp443Obs)
	// Landing-side defense-in-depth: even when entry sets xudpProxyUDP443:allow
	// (positive control: 8443 succeeds), landing's own rule independently denies UDP 443.
	if err := assertSOCKS5UDPEcho("127.0.0.1:19289", "198.51.100.34:8443", "203.0.113.21", 256); err != nil {
		t.Fatalf("dual-role allow443 positive control XUDP 8443 failed: %v", err)
	}
	assertSOCKS5UDPDenied(t, "127.0.0.1:19289", "198.51.100.34:443", udp443Obs)
	assertSOCKS5UDPDenied(t, "127.0.0.1:19280", "192.168.50.3:8443", privUDPObs)

	beforePrivTCP := privTCPObs.total()
	if err := assertSOCKS5TCPEcho("127.0.0.1:19280", "192.168.50.3:8444", "203.0.113.21", 64); err == nil {
		t.Fatal("dual-role fixed landing reached private TCP target")
	}
	if privTCPObs.total() != beforePrivTCP {
		t.Fatalf("dual-role fixed landing leaked private TCP connection: before=%d after=%d", beforePrivTCP, privTCPObs.total())
	}

	if err := assertSOCKS5TCPEcho("127.0.0.1:19281", "198.51.100.34:8444", "203.0.113.51", 256); err != nil {
		t.Fatalf("three-hop landing-1 TCP failed: %v", err)
	}
	if err := assertSOCKS5UDPEcho("127.0.0.1:19281", "198.51.100.34:8443", "203.0.113.51", 256); err != nil {
		t.Fatalf("three-hop landing-1 XUDP failed: %v", err)
	}
	// Same relay-v6 physical edge + same landing-1 node with a second distinct
	// EIH uPSK must independently select fixed exit 203.0.113.53 for TCP and XUDP.
	if err := assertSOCKS5TCPEcho("127.0.0.1:19292", "198.51.100.34:8444", "203.0.113.53", 256); err != nil {
		t.Fatalf("three-hop landing-1 secondary exit TCP failed: %v", err)
	}
	if err := assertSOCKS5UDPEcho("127.0.0.1:19292", "198.51.100.34:8443", "203.0.113.53", 256); err != nil {
		t.Fatalf("three-hop landing-1 secondary exit XUDP failed: %v", err)
	}
	if err := assertSOCKS5TCPEcho("127.0.0.1:19281", "198.51.100.34:8444", "203.0.113.51", 256); err != nil {
		t.Fatalf("three-hop landing-1 primary exit TCP regressed: %v", err)
	}
	if err := assertSOCKS5UDPEcho("127.0.0.1:19281", "198.51.100.34:8443", "203.0.113.51", 256); err != nil {
		t.Fatalf("three-hop landing-1 primary exit XUDP regressed: %v", err)
	}
	if err := assertSOCKS5TCPEcho("127.0.0.1:19282", "198.51.100.34:8444", "203.0.113.52", 256); err != nil {
		t.Fatalf("three-hop landing-2 TCP failed: %v", err)
	}
	// Landing-2 is TCP-only; XUDP over the SAME shared (entry -> relay-dual:24000) edge
	// must be denied by landing-2's own routing rule and never reach the active UDP witness.
	assertSOCKS5UDPDenied(t, "127.0.0.1:19282", "198.51.100.34:8443", udpObs)
	if err := assertSOCKS5TCPEcho("127.0.0.1:19282", "198.51.100.34:8444", "203.0.113.52", 256); err != nil {
		t.Fatalf("three-hop landing-2 TCP regressed after UDP denial: %v", err)
	}

	// IPv4 ingress on port 24000: authorized for landing-1, denied for live landing-2
	// (proves per-credential destination whitelist isolation on relay-dual).
	if err := assertSOCKS5TCPEcho("127.0.0.1:19283", "198.51.100.34:8444", "203.0.113.51", 256); err != nil {
		t.Fatalf("IPv4 ingress on port 24000 -> landing-1 TCP failed: %v", err)
	}
	beforeL2Hits := tcpObs.total()
	if err := assertSOCKS5TCPEcho("127.0.0.1:19290", "198.51.100.34:8444", "203.0.113.52", 64); err == nil {
		t.Fatal("v4 relay credential unexpectedly reached non-authorized live landing-2")
	}
	if tcpObs.total() != beforeL2Hits {
		t.Fatalf("v4 relay credential leaked TCP traffic: before=%d after=%d", beforeL2Hits, tcpObs.total())
	}

	// 2. Relay direct freedom.finalRules destination whitelist with same-family IPv6
	// controls (doc public, ULA private on port 24000, allowed IP wrong port 24001,
	// unauthorized IP on port 24000) plus IPv4 controls and both transport & XUDP UDP checks.
	beforePubTCP := tcpObs.total()
	beforeV6Pub := v6PubTCPObs.total()
	beforeV6Priv := v6PrivTCPObs.total()
	beforeWrongPort := wrongPortTCPObs.total()
	beforeWrongIP := wrongIP24000Obs.total()
	for _, forbidden := range []string{
		"[2001:db8:240::34]:8444",
		"[fd00:240::3]:24000",
		"[2001:db8:240::31]:24001",
		"[2001:db8:240::99]:24000",
		"198.51.100.34:8444",
		"192.168.50.3:8444",
	} {
		if err := assertSOCKS5TCPEcho("127.0.0.1:19284", forbidden, "2001:db8:240::21", 64); err == nil {
			t.Fatalf("relay finalRules unexpectedly allowed forbidden target %s", forbidden)
		}
	}
	if v6PubTCPObs.total() != beforeV6Pub ||
		v6PrivTCPObs.total() != beforeV6Priv ||
		wrongPortTCPObs.total() != beforeWrongPort ||
		wrongIP24000Obs.total() != beforeWrongIP ||
		tcpObs.total() != beforePubTCP ||
		privTCPObs.total() != beforePrivTCP {
		t.Fatalf("relay finalRules leaked forbidden TCP connection: v6pub=%d/%d v6priv=%d/%d wrongPort=%d/%d wrongIP=%d/%d v4pub=%d/%d v4priv=%d/%d",
			beforeV6Pub, v6PubTCPObs.total(),
			beforeV6Priv, v6PrivTCPObs.total(),
			beforeWrongPort, wrongPortTCPObs.total(),
			beforeWrongIP, wrongIP24000Obs.total(),
			beforePubTCP, tcpObs.total(),
			beforePrivTCP, privTCPObs.total())
	}
	// Transport-layer check: raw SS2022 UDP fails against TCP-only 24000.
	assertSOCKS5UDPDenied(t, "127.0.0.1:19284", "198.51.100.34:8443", udpObs)
	// Relay Xray policy-layer check: XUDP tunneled INSIDE TCP 24000 reaches relay-dual's
	// routing table and must be rejected by the relay-role TCP-only rule.
	assertSOCKS5UDPDenied(t, "127.0.0.1:19287", "198.51.100.34:8443", udpObs)
	assertSOCKS5UDPDenied(t, "127.0.0.1:19287", "[2001:db8:240::34]:8443", v6UDPObs)

	// 3. Wrong source IP, missing sendThrough (kernel picks non-authorized loopback
	// source instead of explicit 2001:db8:240::10), unknown uPSK, and genuine
	// before/after EIH uPSK revocation (removing ONLY clients[] while retaining rule).
	beforeAuthHits := tcpObs.total()
	if err := assertSOCKS5TCPEcho("127.0.0.1:19285", "198.51.100.34:8444", "203.0.113.51", 64); err == nil {
		t.Fatal("wrong source IP with valid uPSK unexpectedly passed")
	}
	if err := assertSOCKS5TCPEcho("127.0.0.1:19291", "198.51.100.34:8444", "203.0.113.51", 64); err == nil {
		t.Fatal("relay edge without explicit sendThrough unexpectedly passed")
	}
	if err := assertSOCKS5TCPEcho("127.0.0.1:19286", "198.51.100.34:8444", "203.0.113.51", 64); err == nil {
		t.Fatal("unknown uPSK unexpectedly passed")
	}
	if tcpObs.total() != beforeAuthHits {
		t.Fatalf("unauthorized source, missing sendThrough, or unknown uPSK reached target: before=%d after=%d", beforeAuthHits, tcpObs.total())
	}

	// Prove upskTempRelay works BEFORE revocation.
	if err := assertSOCKS5TCPEcho("127.0.0.1:19288", "198.51.100.34:8444", "203.0.113.51", 256); err != nil {
		t.Fatalf("temporary relay uPSK failed before revocation: %v", err)
	}
	// Apply updated relay-dual config removing ONLY upskTempRelay from clients[]
	// while keeping its routing rule present so denial proves EIH key revocation.
	relayDual.Stop()
	relayDualSpec.includeTempRelayKey = false
	relayDual = startManagedXray(t, ctx, xrayBin, dir, "relay-dual-revoked",
		[]string{"127.0.0.1:19190", "[2001:db8:240::21]:24000", "198.51.100.21:24000"},
		buildDualRoleSinglePort24000Config(relayDualSpec))
	defer relayDual.Stop()

	beforeRevokeHits := tcpObs.total()
	if err := assertSOCKS5TCPEcho("127.0.0.1:19288", "198.51.100.34:8444", "203.0.113.51", 64); err == nil {
		t.Fatal("revoked uPSK unexpectedly passed after removal from clients[]")
	}
	if tcpObs.total() != beforeRevokeHits {
		t.Fatalf("revoked uPSK reached target after removal: before=%d after=%d", beforeRevokeHits, tcpObs.total())
	}
	// Retained credentials MUST continue working unaffected.
	if err := assertSOCKS5TCPEcho("127.0.0.1:19281", "198.51.100.34:8444", "203.0.113.51", 256); err != nil {
		t.Fatalf("retained relay uPSK regressed after revoking peer uPSK: %v", err)
	}
	if err := assertSOCKS5TCPEcho("127.0.0.1:19280", "198.51.100.34:8444", "203.0.113.21", 256); err != nil {
		t.Fatalf("retained landing uPSK regressed after revoking peer uPSK: %v", err)
	}

	// 4. Per-full-path health isolation in ObservatoryService:
	// stopping landing-2 marks ONLY path-l2 unhealthy while path-l1 stays healthy.
	waitObservatoryCondition(t, ctx, "127.0.0.1:19086", 30*time.Second, "both full paths healthy", func(m map[string]observatoryOutboundStatus) bool {
		p1, ok1 := m["path-l1"]
		p2, ok2 := m["path-l2"]
		return ok1 && ok2 && p1.Alive && p2.Alive
	})
	landing2.Stop()
	waitObservatoryCondition(t, ctx, "127.0.0.1:19086", 30*time.Second, "path-l2 unhealthy while path-l1 remains healthy", func(m map[string]observatoryOutboundStatus) bool {
		p1, ok1 := m["path-l1"]
		p2, ok2 := m["path-l2"]
		return ok1 && ok2 && p1.Alive && !p2.Alive
	})
	if err := assertSOCKS5TCPEcho("127.0.0.1:19281", "198.51.100.34:8444", "203.0.113.51", 256); err != nil {
		t.Fatalf("path-l1 regressed when landing-2 stopped: %v", err)
	}
	if err := assertSOCKS5TCPEcho("127.0.0.1:19280", "198.51.100.34:8444", "203.0.113.21", 256); err != nil {
		t.Fatalf("dual-role fixed landing regressed when landing-2 stopped: %v", err)
	}
}

type recoveryMetrics struct {
	tcpRecoveredAt  time.Duration
	xudpRecoveredAt time.Duration
	evictedAt       time.Duration
	tcpFailures     int
	xudpFailures    int
}

func candidateEligible(st observatoryOutboundStatus, maxRTTMS int64, maxTolerance float64) bool {
	if !st.Alive || st.HealthPing == nil || st.HealthPing.All < 1 {
		return false
	}
	if maxRTTMS > 0 && st.DelayMS >= maxRTTMS {
		return false
	}
	if float64(st.HealthPing.Fail)/float64(st.HealthPing.All) > maxTolerance {
		return false
	}
	return true
}

func measureHardFaultRecovery(t *testing.T, ctx context.Context, socksAddr, apiAddr, tcpTarget, udpTarget, wantExitIP string, faultAt time.Time, timeout time.Duration) recoveryMetrics {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var m recoveryMetrics
	tcpStreak, xudpStreak := 0, 0
	var tcpStreakStart, xudpStreakStart time.Duration
	evicted := false

	for {
		if err := assertSOCKS5TCPEchoTimeout(socksAddr, tcpTarget, wantExitIP, 256, 1200*time.Millisecond); err == nil {
			tcpStreak++
			if tcpStreak == 1 {
				tcpStreakStart = time.Since(faultAt)
			}
		} else {
			tcpStreak = 0
			m.tcpFailures++
		}
		if err := assertSOCKS5UDPEcho(socksAddr, udpTarget, wantExitIP, 256); err == nil {
			xudpStreak++
			if xudpStreak == 1 {
				xudpStreakStart = time.Since(faultAt)
			}
		} else {
			xudpStreak = 0
			m.xudpFailures++
		}
		if !evicted {
			callCtx, cancel := context.WithTimeout(ctx, time.Second)
			obs, err := queryObservatoryStatus(callCtx, apiAddr)
			cancel()
			if err == nil {
				r0, ok0 := obs["route-l1-r0"]
				r1, ok1 := obs["route-l1-r1"]
				if ok0 && ok1 && !r0.Alive && r1.Alive {
					evicted = true
					m.evictedAt = time.Since(faultAt)
				}
			}
		}
		if evicted && tcpStreak >= 6 && xudpStreak >= 4 {
			m.tcpRecoveredAt = tcpStreakStart
			m.xudpRecoveredAt = xudpStreakStart
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out measuring hard-fault recovery: evicted=%v tcpStreak=%d xudpStreak=%d tcpFails=%d xudpFails=%d",
				evicted, tcpStreak, xudpStreak, m.tcpFailures, m.xudpFailures)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context canceled during hard-fault recovery: %v", ctx.Err())
		case <-time.After(75 * time.Millisecond):
		}
	}
}

func measureLatencyEvictionRecovery(t *testing.T, ctx context.Context, socksAddr, apiAddr, tcpTarget, udpTarget, wantExitIP string, faultAt time.Time, timeout time.Duration) recoveryMetrics {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var m recoveryMetrics
	tcpFastStreak, xudpFastStreak := 0, 0
	var tcpStreakStart, xudpStreakStart time.Duration
	evicted := false

	for {
		tcpStart := time.Now()
		err := assertSOCKS5TCPEchoTimeout(socksAddr, tcpTarget, wantExitIP, 256, 2*time.Second)
		tcpDur := time.Since(tcpStart)
		if err == nil && tcpDur < 150*time.Millisecond {
			tcpFastStreak++
			if tcpFastStreak == 1 {
				tcpStreakStart = time.Since(faultAt)
			}
		} else {
			tcpFastStreak = 0
			m.tcpFailures++
		}
		udpStart := time.Now()
		err = assertSOCKS5UDPEcho(socksAddr, udpTarget, wantExitIP, 256)
		udpDur := time.Since(udpStart)
		if err == nil && udpDur < 150*time.Millisecond {
			xudpFastStreak++
			if xudpFastStreak == 1 {
				xudpStreakStart = time.Since(faultAt)
			}
		} else {
			xudpFastStreak = 0
			m.xudpFailures++
		}
		if !evicted {
			callCtx, cancel := context.WithTimeout(ctx, time.Second)
			obs, err := queryObservatoryStatus(callCtx, apiAddr)
			cancel()
			if err == nil {
				r0, ok0 := obs["route-l1-r0"]
				r1, ok1 := obs["route-l1-r1"]
				if ok0 && ok1 && r0.Alive && r0.DelayMS >= 200 && r1.Alive && r1.DelayMS < 120 {
					evicted = true
					m.evictedAt = time.Since(faultAt)
				}
			}
		}
		if evicted && tcpFastStreak >= 6 && xudpFastStreak >= 4 {
			m.tcpRecoveredAt = tcpStreakStart
			m.xudpRecoveredAt = xudpStreakStart
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out measuring maxRTT gray-failure recovery: evicted=%v tcpFast=%d xudpFast=%d slowTCP=%d slowUDP=%d",
				evicted, tcpFastStreak, xudpFastStreak, m.tcpFailures, m.xudpFailures)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context canceled during maxRTT gray-failure recovery: %v", ctx.Err())
		case <-time.After(75 * time.Millisecond):
		}
	}
}

func requireRelayPoolNamespace(t *testing.T) string {
	t.Helper()
	if os.Getenv("GLIVELA_RELAY_POOL_CORE_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	udpRuntimeNamespace(t, 0)
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh loopback-only namespace required", err)
	}
	core := os.Getenv("GLIVELA_XRAY_BINARY")
	if !filepath.IsAbs(core) {
		t.Fatal("verified official core path required")
	}
	checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := exec.CommandContext(checkCtx, core, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(version), "Xray 26.11.9 ") {
		t.Fatalf("packaged Xray 26.11.9 required, got %q %v", string(version), err)
	}
	return core
}

func setupRelayPoolLoopback(t *testing.T, ctx context.Context, v4Addrs, v6Addrs []string) {
	t.Helper()
	runIP := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, string(out), err)
		}
	}
	runIP("link", "set", "lo", "up")
	for _, a := range v4Addrs {
		runIP("addr", "add", a, "dev", "lo")
	}
	for _, a := range v6Addrs {
		runIP("-6", "addr", "add", a, "dev", "lo", "nodad")
	}
}

type managedXray struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	logFile *os.File
	stopped bool
}

func (m *managedXray) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	cmd, logFile := m.cmd, m.logFile
	m.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if logFile != nil {
		_ = logFile.Close()
	}
}

func startManagedXray(t *testing.T, ctx context.Context, binaryPath, dir, name string, readyAddrs []string, cfg map[string]any) *managedXray {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, name+".json")
	if err := os.WriteFile(cfgPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, binaryPath, "run", "-test", "-config", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("xray -test %s failed: %v\n%s", name, err, string(out))
	}
	logPath := filepath.Join(dir, name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binaryPath, "run", "-config", cfgPath)
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=64MiB", "GOGC=50")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	handle := &managedXray{cmd: cmd, logFile: logFile}
	t.Cleanup(func() {
		handle.Stop()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			if len(data) > 6000 {
				data = data[len(data)-6000:]
			}
			t.Logf("=== %s log ===\n%s", name, string(data))
		}
	})
	// Wait for BOTH API and every business TCP listener so tests never race
	// Commander startup against InboundManager socket binding.
	deadline := time.Now().Add(5 * time.Second)
	for _, addr := range readyAddrs {
		for {
			c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if e == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("xray %s listener %s unavailable: %v", name, addr, e)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	return handle
}

type relayProxyMode int32

const (
	relayProxyPass relayProxyMode = iota
	relayProxyReset
	relayProxyBlackhole
)

type controllableRelayProxy struct {
	listenAddr string
	targetAddr string
	sourceIP   string
	attempts   atomic.Int64
	mu         sync.Mutex
	ln         net.Listener
	listenGen  uint64
	epoch      uint64
	mode       relayProxyMode
	delay      time.Duration
	active     map[net.Conn]struct{}
}

func newControllableRelayProxy(t *testing.T, listenAddr, targetAddr, sourceIP string) *controllableRelayProxy {
	t.Helper()
	p := &controllableRelayProxy{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		sourceIP:   sourceIP,
		active:     map[net.Conn]struct{}{},
	}
	t.Cleanup(p.StopListener)
	return p
}

func (p *controllableRelayProxy) StartListener(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	if p.ln != nil {
		p.mu.Unlock()
		return
	}
	var ln net.Listener
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln, err = net.Listen("tcp6", p.listenAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			p.mu.Unlock()
			t.Fatalf("listen %s failed: %v", p.listenAddr, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	p.listenGen++
	myListenGen := p.listenGen
	p.ln = ln
	p.mu.Unlock()

	go func(listener net.Listener, gen uint64) {
		for {
			in, e := listener.Accept()
			if e != nil {
				return
			}
			go p.handleConn(gen, in)
		}
	}(ln, myListenGen)
}

// StopListener advances listenGen and epoch under lock before releasing and
// closing the listener and all active sockets, so already-accepted connections
// cannot register or dial upstream after StopListener returns.
func (p *controllableRelayProxy) StopListener() {
	p.mu.Lock()
	p.listenGen++
	p.epoch++
	ln := p.ln
	p.ln = nil
	conns := p.drainActiveLocked()
	p.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *controllableRelayProxy) SetMode(m relayProxyMode) {
	p.mu.Lock()
	p.epoch++
	p.mode = m
	conns := p.drainActiveLocked()
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *controllableRelayProxy) SetDelay(d time.Duration) {
	p.mu.Lock()
	p.epoch++
	p.delay = d
	conns := p.drainActiveLocked()
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *controllableRelayProxy) Attempts() int64 {
	return p.attempts.Load()
}

func (p *controllableRelayProxy) drainActiveLocked() []net.Conn {
	conns := make([]net.Conn, 0, len(p.active))
	for c := range p.active {
		conns = append(conns, c)
	}
	clear(p.active)
	return conns
}

func (p *controllableRelayProxy) beginConn(listenGen uint64, client net.Conn) (uint64, relayProxyMode, time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil || p.listenGen != listenGen {
		return 0, 0, 0, false
	}
	p.attempts.Add(1)
	p.active[client] = struct{}{}
	return p.epoch, p.mode, p.delay, true
}

func (p *controllableRelayProxy) registerUpstream(epoch uint64, out net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil || p.epoch != epoch {
		return false
	}
	p.active[out] = struct{}{}
	return true
}

func (p *controllableRelayProxy) epochCurrent(epoch uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ln != nil && p.epoch == epoch
}

func (p *controllableRelayProxy) unregisterConn(c net.Conn) {
	p.mu.Lock()
	delete(p.active, c)
	p.mu.Unlock()
}

func (p *controllableRelayProxy) handleConn(listenGen uint64, client net.Conn) {
	epoch, mode, delay, ok := p.beginConn(listenGen, client)
	if !ok {
		_ = client.Close()
		return
	}
	defer func() {
		p.unregisterConn(client)
		_ = client.Close()
	}()

	switch mode {
	case relayProxyReset:
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		return
	case relayProxyBlackhole:
		_, _ = io.Copy(io.Discard, client)
		return
	}

	if delay > 0 {
		time.Sleep(delay)
		if !p.epochCurrent(epoch) {
			return
		}
	}

	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(p.sourceIP)},
		Timeout:   2 * time.Second,
	}
	out, err := dialer.Dial("tcp6", p.targetAddr)
	if err != nil {
		return
	}
	if !p.registerUpstream(epoch, out) {
		_ = out.Close()
		return
	}
	defer func() {
		p.unregisterConn(out)
		_ = out.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}
	go copyHalf(out, client)
	go copyHalf(client, out)
	wg.Wait()
}

func testBlockedIPv4Except(allowedPrefix string) []string {
	out := make([]string, 0, len(blockedIPv4))
	for _, cidr := range blockedIPv4 {
		if cidr == allowedPrefix {
			continue
		}
		out = append(out, cidr)
	}
	return out
}

type eihRouteClient struct {
	email      string
	upsk       string
	sourceCIDR string
	allowUDP   bool
	egressIP   string
}

type eihLandingSpec struct {
	apiPort       int
	listenIPv6    string
	serverIPSK    string
	defaultEgress string
	clients       []eihRouteClient
}

func buildEIHLandingConfig(spec eihLandingSpec) map[string]any {
	clients := make([]any, 0, len(spec.clients))
	blockedRouteIPs := append(testBlockedIPv4Except("198.51.100.0/24"), "::/0")
	rules := []any{
		map[string]any{"type": "field", "ip": blockedRouteIPs, "outboundTag": "deny"},
	}
	makeEgressOutbound := func(tag, sendThrough string) map[string]any {
		return map[string]any{
			"tag":         tag,
			"protocol":    "freedom",
			"sendThrough": sendThrough,
			"settings": map[string]any{
				"targetStrategy": "ForceIPv4",
				// Allow only the synthetic documentation witness target while retaining
				// full RFC1918 and special-purpose blocks for negative controls.
				"finalRules": []any{
					map[string]any{"action": "allow", "ip": []string{relayPoolDocTargetCIDR}},
					map[string]any{"action": "block", "ip": append(slices.Clone(blockedIPv4), "::/0"), "blockDelay": "0"},
				},
			},
		}
	}
	outbounds := []any{
		map[string]any{"tag": "deny", "protocol": "blackhole"},
		makeEgressOutbound("egress", spec.defaultEgress),
	}
	for _, c := range spec.clients {
		clients = append(clients, map[string]any{"password": c.upsk, "email": c.email, "level": 0})
		outboundTag := "egress"
		if c.egressIP != "" && c.egressIP != spec.defaultEgress {
			outboundTag = "egress-" + c.email
			outbounds = append(outbounds, makeEgressOutbound(outboundTag, c.egressIP))
		}
		if c.allowUDP {
			rules = append(rules,
				map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{c.email}, "source": []string{c.sourceCIDR}, "network": "udp", "port": "443", "outboundTag": "deny"},
				map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{c.email}, "source": []string{c.sourceCIDR}, "network": "tcp,udp", "outboundTag": outboundTag},
			)
		} else {
			rules = append(rules,
				map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{c.email}, "source": []string{c.sourceCIDR}, "network": "tcp", "outboundTag": outboundTag},
			)
		}
	}
	return map[string]any{
		"log":   map[string]any{"loglevel": "warning", "access": "none"},
		"api":   map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", spec.apiPort), "services": []string{"StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
		},
		"inbounds": []any{
			map[string]any{
				"tag":      "ss-v6-24000",
				"listen":   spec.listenIPv6,
				"port":     24000,
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   glivela.SS2022Method,
					"password": spec.serverIPSK,
					"network":  "tcp",
					"clients":  clients,
				},
			},
		},
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
}

type eihRelayUser struct {
	email      string
	upsk       string
	sourceCIDR string
}

func buildEIHRelayOnlyConfig(apiPort int, listenIPv6, serverIPSK string, users []eihRelayUser, allowedLandingCIDRs []string) map[string]any {
	clients := make([]any, 0, len(users))
	rules := make([]any, 0, len(users))
	for _, u := range users {
		clients = append(clients, map[string]any{"password": u.upsk, "email": u.email, "level": 0})
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []string{"ss-v6-24000"},
			"user":        []string{u.email},
			"source":      []string{u.sourceCIDR},
			"network":     "tcp",
			"outboundTag": "relay-egress",
		})
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"api": map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"StatsService"}},
		"inbounds": []any{
			map[string]any{
				"tag":      "ss-v6-24000",
				"listen":   listenIPv6,
				"port":     24000,
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   glivela.SS2022Method,
					"password": serverIPSK,
					"network":  "tcp",
					"clients":  clients,
				},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "deny", "protocol": "blackhole"},
			// Direct freedom outbound (no dialerProxy) so finalRules strictly limits
			// relay egress to authorized downstream landing IP:24000/TCP.
			map[string]any{
				"tag":         "relay-egress",
				"protocol":    "freedom",
				"sendThrough": listenIPv6,
				"settings": map[string]any{
					"targetStrategy": "ForceIPv6",
					"finalRules": []any{
						map[string]any{"action": "allow", "network": "tcp", "ip": allowedLandingCIDRs, "port": "24000"},
						map[string]any{"action": "block", "ip": []string{"0.0.0.0/0", "::/0"}, "blockDelay": "0"},
					},
				},
			},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
}

type dualRoleSpec struct {
	apiPort             int
	listenIPv6          string
	listenIPv4          string
	serverIPSK          string
	landingEgressV4     string
	upskV6Landing       string
	upskV6Relay         string
	upskTempRelay       string
	upskV4Relay         string
	entryV6CIDR         string
	entryV4CIDR         string
	v6AllowedLandings   []string
	v4AllowedLandings   []string
	includeTempRelayKey bool
}

func buildDualRoleSinglePort24000Config(spec dualRoleSpec) map[string]any {
	blockedRouteIPs := append(testBlockedIPv4Except("198.51.100.0/24"), "::/0")
	v6Clients := []any{
		map[string]any{"password": spec.upskV6Landing, "email": "entry-v6-landing", "level": 0},
		map[string]any{"password": spec.upskV6Relay, "email": "entry-v6-relay", "level": 0},
	}
	if spec.includeTempRelayKey {
		v6Clients = append(v6Clients, map[string]any{"password": spec.upskTempRelay, "email": "entry-v6-temp-relay", "level": 0})
	}
	// Keep the entry-v6-temp-relay routing rule unconditionally so revocation
	// proves SS2022 EIH clients[] removal independently rejects the key.
	rules := []any{
		// Landing-role rules (TCP + XUDP, block UDP 443 and private/blocked IPs).
		map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{"entry-v6-landing"}, "source": []string{spec.entryV6CIDR}, "network": "udp", "port": "443", "outboundTag": "deny"},
		map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{"entry-v6-landing"}, "source": []string{spec.entryV6CIDR}, "ip": blockedRouteIPs, "outboundTag": "deny"},
		map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{"entry-v6-landing"}, "source": []string{spec.entryV6CIDR}, "network": "tcp,udp", "outboundTag": "landing-egress-v4"},
		// Per-credential relay-role rules (TCP-only, isolated destination whitelists).
		map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{"entry-v6-relay"}, "source": []string{spec.entryV6CIDR}, "network": "tcp", "outboundTag": "relay-egress-v6"},
		map[string]any{"type": "field", "inboundTag": []string{"ss-v6-24000"}, "user": []string{"entry-v6-temp-relay"}, "source": []string{spec.entryV6CIDR}, "network": "tcp", "outboundTag": "relay-egress-v6"},
		map[string]any{"type": "field", "inboundTag": []string{"ss-v4-24000"}, "user": []string{"entry-v4-relay"}, "source": []string{spec.entryV4CIDR}, "network": "tcp", "outboundTag": "relay-egress-v4-l1-only"},
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"api": map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", spec.apiPort), "services": []string{"StatsService"}},
		"inbounds": []any{
			map[string]any{
				"tag":      "ss-v6-24000",
				"listen":   spec.listenIPv6,
				"port":     24000,
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   glivela.SS2022Method,
					"password": spec.serverIPSK,
					"network":  "tcp",
					"clients":  v6Clients,
				},
			},
			map[string]any{
				"tag":      "ss-v4-24000",
				"listen":   spec.listenIPv4,
				"port":     24000,
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"method":   glivela.SS2022Method,
					"password": spec.serverIPSK,
					"network":  "tcp",
					"clients": []any{
						map[string]any{"password": spec.upskV4Relay, "email": "entry-v4-relay", "level": 0},
					},
				},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "deny", "protocol": "blackhole"},
			map[string]any{
				"tag":         "landing-egress-v4",
				"protocol":    "freedom",
				"sendThrough": spec.landingEgressV4,
				"settings": map[string]any{
					"targetStrategy": "ForceIPv4",
					"finalRules": []any{
						map[string]any{"action": "allow", "ip": []string{relayPoolDocTargetCIDR}},
						map[string]any{"action": "block", "ip": append(slices.Clone(blockedIPv4), "::/0"), "blockDelay": "0"},
					},
				},
			},
			map[string]any{
				"tag":         "relay-egress-v6",
				"protocol":    "freedom",
				"sendThrough": spec.listenIPv6,
				"settings": map[string]any{
					"targetStrategy": "ForceIPv6",
					"finalRules": []any{
						map[string]any{"action": "allow", "network": "tcp", "ip": spec.v6AllowedLandings, "port": "24000"},
						map[string]any{"action": "block", "ip": []string{"0.0.0.0/0", "::/0"}, "blockDelay": "0"},
					},
				},
			},
			map[string]any{
				"tag":         "relay-egress-v4-l1-only",
				"protocol":    "freedom",
				"sendThrough": spec.listenIPv6,
				"settings": map[string]any{
					"targetStrategy": "ForceIPv6",
					"finalRules": []any{
						map[string]any{"action": "allow", "network": "tcp", "ip": spec.v4AllowedLandings, "port": "24000"},
						map[string]any{"action": "block", "ip": []string{"0.0.0.0/0", "::/0"}, "blockDelay": "0"},
					},
				},
			},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules":          rules,
		},
	}
}

type entryRelaySpec struct {
	tag      string
	addr     string
	password string
}

type entryCandidateSpec struct {
	tag             string
	relayTag        string
	landingAddr     string
	landingPassword string
	udp             bool
}

type entryPoolSpec struct {
	apiPort       int
	socksPort     int
	emptyPoolPort int
	entryIPv6     string
	decoyDirectV4 string
	probeURL      string
	maxRTT        string
	relays        []entryRelaySpec
	candidates    []entryCandidateSpec
	expected      int
	fallbackTag   string
}

func buildRelayPoolEntryConfig(spec entryPoolSpec) map[string]any {
	// Place decoy direct outbound first to detect any unintended fallback to default outbound[0].
	outbounds := []any{
		map[string]any{"tag": "decoy-direct", "protocol": "freedom", "sendThrough": spec.decoyDirectV4},
		map[string]any{"tag": "blocked", "protocol": "blackhole"},
	}
	for _, r := range spec.relays {
		outbounds = append(outbounds, ss2022ClientOutbound(r.tag, r.addr, 24000, r.password, spec.entryIPv6, "", false, ""))
	}
	for _, c := range spec.candidates {
		outbounds = append(outbounds, ss2022ClientOutbound(c.tag, c.landingAddr, 24000, c.landingPassword, "", c.relayTag, c.udp, "reject"))
	}
	prefix := spec.candidates[0].tag
	if idx := strings.LastIndex(prefix, "-r"); idx > 0 {
		prefix = prefix[:idx+2]
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"api": map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", spec.apiPort), "services": []string{"ObservatoryService"}},
		"burstObservatory": map[string]any{
			"subjectSelector": []string{prefix},
			"pingConfig": map[string]any{
				"destination": spec.probeURL,
				"interval":    "10s",
				"sampling":    1,
				"timeout":     "1s",
			},
		},
		"inbounds": []any{
			socksTestInbound("socks-pool", spec.socksPort),
			socksTestInbound("socks-empty", spec.emptyPoolPort),
		},
		"outbounds": outbounds,
		"routing": map[string]any{
			"balancers": []any{
				map[string]any{
					"tag":         "bal-pool",
					"selector":    []string{prefix},
					"fallbackTag": spec.fallbackTag,
					"strategy": map[string]any{
						"type": "leastLoad",
						"settings": map[string]any{
							"expected":  spec.expected,
							"maxRTT":    spec.maxRTT,
							"tolerance": 0.25,
						},
					},
				},
			},
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []string{"socks-pool"}, "balancerTag": "bal-pool"},
				map[string]any{"type": "field", "inboundTag": []string{"socks-empty"}, "outboundTag": "blocked"},
			},
		},
	}
}

func socksTestInbound(tag string, port int) map[string]any {
	return map[string]any{
		"tag":      tag,
		"listen":   "127.0.0.1",
		"port":     port,
		"protocol": "socks",
		"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
	}
}

func ss2022ClientOutbound(tag, addr string, port int, password, sendThrough, dialerProxy string, udp bool, udp443Policy string) map[string]any {
	out := map[string]any{
		"tag":      tag,
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []any{
				map[string]any{
					"address":  addr,
					"port":     port,
					"method":   glivela.SS2022Method,
					"password": password,
				},
			},
		},
	}
	if sendThrough != "" {
		out["sendThrough"] = sendThrough
	}
	if dialerProxy != "" {
		out["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": dialerProxy}}
	}
	if udp {
		if udp443Policy == "" {
			udp443Policy = "reject"
		}
		out["mux"] = map[string]any{"enabled": true, "concurrency": -1, "xudpConcurrency": 1, "xudpProxyUDP443": udp443Policy}
	}
	return out
}

type controllableProbeServer struct {
	mu      sync.Mutex
	holdCh  chan struct{}
	holding bool
	drop    atomic.Bool
}

func (p *controllableProbeServer) SetHold(hold bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if hold && !p.holding {
		p.holdCh = make(chan struct{})
		p.holding = true
	} else if !hold && p.holding {
		close(p.holdCh)
		p.holding = false
	}
}

func (p *controllableProbeServer) SetDrop(drop bool) {
	p.drop.Store(drop)
}

func (p *controllableProbeServer) waitHold(ctx context.Context) {
	p.mu.Lock()
	holding := p.holding
	ch := p.holdCh
	p.mu.Unlock()
	if !holding {
		return
	}
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

func startControllableProbeServer(t *testing.T, addr string) *controllableProbeServer {
	t.Helper()
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctrl := &controllableProbeServer{}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctrl.waitHold(r.Context())
			if ctrl.drop.Load() {
				if hj, ok := w.(http.Hijacker); ok {
					if c, _, err := hj.Hijack(); err == nil {
						_ = c.Close()
						return
					}
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctrl.SetHold(false)
		_ = srv.Close()
	})
	return ctrl
}

type observedSources struct {
	mu  sync.Mutex
	ips map[string]int
}

func (o *observedSources) record(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	o.mu.Lock()
	o.ips[host]++
	o.mu.Unlock()
	return host
}

func (o *observedSources) count(ip string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ips[ip]
}

func (o *observedSources) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	sum := 0
	for _, n := range o.ips {
		sum += n
	}
	return sum
}

func startSourceEchoTCPServer(t *testing.T, addr string) *observedSources {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	obs := &observedSources{ips: map[string]int{}}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				host := obs.record(conn.RemoteAddr().String())
				var lenBuf [4]byte
				if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint32(lenBuf[:]))
				if size <= 0 || size > 1<<20 {
					return
				}
				payload := make([]byte, size)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}
				prefix := []byte("observed=" + host + ";")
				_, _ = conn.Write(append(prefix, payload...))
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return obs
}

func startSourceEchoUDPServer(t *testing.T, addr string) *observedSources {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	obs := &observedSources{ips: map[string]int{}}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remote, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			host := obs.record(remote.String())
			reply := append([]byte("observed="+host+";"), buf[:n]...)
			_, _ = pc.WriteTo(reply, remote)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return obs
}

func verifyTCPWitnessReachable(t *testing.T, targetAddr, localIP string) {
	t.Helper()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}, Timeout: time.Second}
	c, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		t.Fatalf("direct TCP witness %s unreachable: %v", targetAddr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("probe")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := c.Write(append(lenBuf[:], payload...)); err != nil {
		t.Fatalf("direct TCP witness %s write failed: %v", targetAddr, err)
	}
	want := []byte("observed=" + localIP + ";probe")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("direct TCP witness %s reply mismatch: %v %q", targetAddr, err, string(got))
	}
}

func verifyUDPWitnessReachable(t *testing.T, targetAddr, localIP string) {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	network := "udp4"
	if dst.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(localIP)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	nonce := udpRuntimeNonce(t)
	if _, err := conn.WriteToUDP([]byte(nonce), dst); err != nil {
		t.Fatalf("direct UDP witness %s write failed: %v", targetAddr, err)
	}
	var buf [512]byte
	n, _, err := conn.ReadFromUDP(buf[:])
	want := "observed=" + localIP + ";" + nonce
	if err != nil || string(buf[:n]) != want {
		t.Fatalf("direct UDP witness %s reply mismatch: %v %q", targetAddr, err, string(buf[:n]))
	}
}

func socks5AddressHeader(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("literal IP required: %s", target)
	}
	if v4 := ip.To4(); v4 != nil {
		b := make([]byte, 0, 1+4+2)
		b = append(b, 1)
		b = append(b, v4...)
		return binary.BigEndian.AppendUint16(b, uint16(port)), nil
	}
	b := make([]byte, 0, 1+16+2)
	b = append(b, 4)
	b = append(b, ip.To16()...)
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func assertSOCKS5TCPEcho(proxyAddr, targetAddr, wantExitIP string, payloadSize int) error {
	return assertSOCKS5TCPEchoTimeout(proxyAddr, targetAddr, wantExitIP, payloadSize, 3*time.Second)
}

func assertSOCKS5TCPEchoTimeout(proxyAddr, targetAddr, wantExitIP string, payloadSize int, deadline time.Duration) error {
	c, err := net.DialTimeout("tcp4", proxyAddr, deadline)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(deadline))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil || method != [2]byte{5, 0} {
		return fmt.Errorf("socks5 greeting: %v %x", err, method)
	}
	addrBytes, err := socks5AddressHeader(targetAddr)
	if err != nil {
		return err
	}
	req := append([]byte{5, 1, 0}, addrBytes...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[1] != 0 {
		return fmt.Errorf("socks5 connect rejected: %v %x", err, header)
	}
	skipLen := 6
	if header[3] == 4 {
		skipLen = 18
	} else if header[3] != 1 {
		return fmt.Errorf("unexpected socks5 reply atyp=%d", header[3])
	}
	if _, err := io.ReadFull(c, make([]byte, skipLen)); err != nil {
		return err
	}
	payload := bytes.Repeat([]byte{'a'}, payloadSize)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := c.Write(append(lenBuf[:], payload...)); err != nil {
		return err
	}
	wantPrefix := []byte("observed=" + wantExitIP + ";")
	got := make([]byte, len(wantPrefix)+len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.HasPrefix(got, wantPrefix) || !bytes.Equal(got[len(wantPrefix):], payload) {
		return fmt.Errorf("unexpected TCP echo prefix=%q", string(got[:min(len(got), 48)]))
	}
	return nil
}

func assertSOCKS5UDPEcho(proxyAddr, targetAddr, wantExitIP string, payloadSize int) error {
	control, relay, err := udpRuntimeAssociate("127.0.0.1", proxyAddr)
	if err != nil {
		return err
	}
	defer control.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return err
	}
	defer u.Close()
	addrBytes, err := socks5AddressHeader(targetAddr)
	if err != nil {
		return err
	}
	header := append([]byte{0, 0, 0}, addrBytes...)
	payload := bytes.Repeat([]byte{'u'}, payloadSize)
	got, err := udpRuntimeExchangeOn(u, relay, append(append([]byte(nil), header...), payload...))
	if err != nil {
		return err
	}
	wantPrefix := append(append([]byte(nil), header...), []byte("observed="+wantExitIP+";")...)
	if !bytes.HasPrefix(got, wantPrefix) || !bytes.Equal(got[len(wantPrefix):], payload) {
		return fmt.Errorf("unexpected UDP echo len=%d", len(got))
	}
	return nil
}

// assertSOCKS5UDPDenied requires SOCKS5 UDP ASSOCIATE and datagram send to
// succeed, then asserts a bounded read timeout and zero new packets from ANY
// source IP observed at the already-live witness target.
func assertSOCKS5UDPDenied(t *testing.T, proxyAddr, destination string, witness *observedSources) {
	t.Helper()
	control, relay, err := udpRuntimeAssociate("127.0.0.1", proxyAddr)
	if err != nil {
		t.Fatalf("SOCKS5 UDP associate %s failed before testing denial of %s: %v", proxyAddr, destination, err)
	}
	defer control.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	addrBytes, err := socks5AddressHeader(destination)
	if err != nil {
		t.Fatal(err)
	}
	beforeTotal := witness.total()
	pkt := append(append([]byte{0, 0, 0}, addrBytes...), []byte(udpRuntimeNonce(t))...)
	if _, err := u.WriteToUDP(pkt, mustUDPAddress(t, relay)); err != nil {
		t.Fatalf("SOCKS5 UDP write to %s failed: %v", destination, err)
	}
	_ = u.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	var reply [2048]byte
	n, _, err := u.ReadFromUDP(reply[:])
	if err == nil {
		t.Fatalf("forbidden UDP destination %s unexpectedly replied (%d bytes)", destination, n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected bounded UDP timeout for %s, got setup/transport error: %v", destination, err)
	}
	if afterTotal := witness.total(); afterTotal != beforeTotal {
		t.Fatalf("forbidden UDP destination %s reached witness from some source (before=%d after=%d)", destination, beforeTotal, afterTotal)
	}
}

func queryLandingRelayUplink(t *testing.T, ctx context.Context, binaryPath, apiAddr string) (int64, int64) {
	t.Helper()
	out, err := exec.CommandContext(ctx, binaryPath, "api", "statsquery", "--server="+apiAddr).Output()
	if err != nil {
		t.Fatalf("xray api statsquery %s failed: %v", apiAddr, err)
	}
	var resp struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode statsquery: %v (%s)", err, string(out))
	}
	parseVal := func(raw json.RawMessage) int64 {
		s := strings.TrimSpace(string(raw))
		if s == "" || s == "null" {
			return 0
		}
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			s = s[1 : len(s)-1]
		}
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("parse stat value %q: %v", s, err)
		}
		return v
	}
	var a, b int64
	for _, s := range resp.Stat {
		switch s.Name {
		case "user>>>relay-a>>>traffic>>>uplink":
			a = parseVal(s.Value)
		case "user>>>relay-b>>>traffic>>>uplink":
			b = parseVal(s.Value)
		}
	}
	return a, b
}

func waitObservatoryCondition(t *testing.T, ctx context.Context, apiAddr string, timeout time.Duration, desc string, pred func(map[string]observatoryOutboundStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]observatoryOutboundStatus
	var lastErr error
	for {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		last, lastErr = queryObservatoryStatus(callCtx, apiAddr)
		cancel()
		if lastErr == nil && pred(last) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: err=%v last=%+v", desc, lastErr, last)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context canceled waiting for %s: %v", desc, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func assertNoUDPPort24000(t *testing.T, ctx context.Context) {
	t.Helper()
	out, err := exec.CommandContext(ctx, "ss", "-H", "-lun").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ":24000") {
		t.Fatalf("unexpected public UDP 24000 listener:\n%s", string(out))
	}
}

func assertNoDecoyDirectHits(t *testing.T, tcpObs, udpObs *observedSources, decoyIP string) {
	t.Helper()
	if tcpObs.count(decoyIP) != 0 || udpObs.count(decoyIP) != 0 {
		t.Fatalf("traffic leaked through decoy direct outbound %s (tcp=%d udp=%d)", decoyIP, tcpObs.count(decoyIP), udpObs.count(decoyIP))
	}
}
