import { describe, expect, it } from "vitest";
import { latencyKey, type RouteLatency } from "./RouteLatency";
import type { Inventory, Route, SocketCutoverPlan } from "./control-types";
import {
  buildEntryRelayConfigPayload,
  buildRelayPoolChangePayload,
  buildRouteChangePayload,
  buildTopologyModel,
  canStartSocketCutover,
  evaluateObservatorySample,
  isEntryPoolSelectedOrConnected,
  isLegacyEdgeSelectedOrConnected,
  isPathSelectedOrConnected,
  isTwoHopSelectedOrConnected,
  isValidDisplayName,
  isValidIdentifier,
  routeTopologyKind,
  summarizePooledRoute,
  validateObservatoryDraft,
  validatePoolDraft,
} from "./relay-pool-model";

const sampleInventory = (nowMs: number): Inventory => ({
  state: "owned",
  accounts: [
    {
      account: { id: "acct-1", displayName: "Demo Account", desiredRevision: "7", plan: { totalBytes: "0", expiryTime: "0", resetDays: 0, enabled: true } },
      usage: [],
      schedule: { nextResetAt: "" },
      traffic: {},
    },
  ],
  endpoints: [{ id: "ep-1", entryId: "entry-a", nodeId: "entry-a", name: "Entry A", retired: false }],
  nodes: [
    { id: "entry-a", name: "Entry A" },
    { id: "relay-1", name: "Relay One" },
    { id: "relay-2", name: "Relay Two" },
    { id: "landing-direct", name: "Landing Direct" },
    { id: "landing-fixed", name: "Landing Fixed" },
  ],
  runtimes: [
    { id: "entry-a", role: "entry", revision: "5", appliedRevision: "5", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.2", reportedAt: new Date(nowMs - 5_000).toISOString(), peers: ["landing-direct"] },
    { id: "relay-1", certificateId: "a".repeat(64), role: "landing", revision: "3", appliedRevision: "3", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.11", egressIp: "198.51.100.11", reportedAt: new Date(nowMs - 5_000).toISOString(), peers: [] },
    { id: "relay-2", certificateId: "b".repeat(64), role: "landing", revision: "4", appliedRevision: "2", runtimeReady: false, relayPoolCapable: true, publicIpv4: "198.51.100.12", egressIp: "198.51.100.12", reportedAt: new Date(nowMs - 300_000).toISOString(), peers: [] },
    { id: "landing-direct", certificateId: "c".repeat(64), role: "landing", revision: "2", appliedRevision: "2", runtimeReady: true, publicIpv4: "198.51.100.20", egressIp: "203.0.113.20", reportedAt: new Date(nowMs - 5_000).toISOString(), peers: [] },
    { id: "landing-fixed", certificateId: "d".repeat(64), role: "landing", revision: "6", appliedRevision: "6", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.30", egressIp: "203.0.113.30", reportedAt: new Date(nowMs - 5_000).toISOString(), peers: [] },
  ],
  relayPools: [
    {
      id: "pool-east",
      name: "East Pool",
      revision: "3",
      strategy: { expected: 2, maxRttMs: 400, tolerance: 0.05 },
      members: [
        { nodeId: "relay-1", certificateId: "a".repeat(64), ingressIpv4: "198.51.100.11", egressIpv4: "198.51.100.11", drained: false, nodeSuspended: false, runtimeReady: true },
        { nodeId: "relay-2", certificateId: "b".repeat(64), ingressIpv4: "198.51.100.12", egressIpv4: "198.51.100.12", drained: false, nodeSuspended: false, runtimeReady: false },
      ],
      routeIds: ["route-pooled"],
      revocation: { pendingEntries: [], pendingLandings: [], complete: true },
    },
  ],
  entryRelayConfigs: {
    "entry-a": {
      revision: "2",
      sourceIpv4: "198.51.100.2",
      observatory: { destination: "https://www.gstatic.com/generate_204", intervalSec: 20, sampling: 3, timeoutSec: 5 },
    },
  },
  observatoryPaths: [
    {
      entryId: "entry-a",
      grantId: "route-pooled",
      poolId: "pool-east",
      relayNodeId: "relay-1",
      egressId: "landing-fixed",
      outboundTag: "pool-0-0",
      alive: true,
      delayMs: 38,
      averageMs: 40,
      minMs: 35,
      maxMs: 46,
      allSamples: 3,
      failedSamples: 0,
      sampledAt: new Date(nowMs - 10_000).toISOString(),
    },
  ],
  routes: [
    {
      id: "route-twohop",
      accountId: "acct-1",
      entryId: "entry-a",
      egressId: "landing-direct",
      port: 1080,
      enabled: true,
      hideNative: false,
      state: "verified",
    },
    {
      id: "route-pooled",
      accountId: "acct-1",
      entryId: "entry-a",
      egressId: "landing-fixed",
      relayPoolId: "pool-east",
      activeRelays: 1,
      activeRelayIds: ["relay-1"],
      landingAddress: "198.51.100.30",
      expectedExit: "203.0.113.30",
      egressIp: "203.0.113.30",
      name: "Fixed Pooled",
      port: 24000,
      enabled: true,
      hideNative: true,
      udp: true,
      state: "verified",
    },
  ],
});

describe("relay-pool-model payloads and validation", () => {
  it("strips view-only BusinessRoute fields in buildRouteChangePayload while preserving explicit udp boolean", () => {
    const route: Route = {
      id: "route-pooled",
      accountId: "acct-1",
      entryId: "entry-a",
      egressId: "landing-fixed",
      relayPoolId: "pool-east",
      pendingRelayPoolId: "pool-east",
      pendingLegacyCutover: false,
      retiringLegacyTransport: true,
      relayId: "relay-legacy",
      activeRelays: 2,
      activeRelayIds: ["relay-1", "relay-2"],
      landingAddress: "198.51.100.30",
      expectedExit: "203.0.113.30",
      egressIp: "203.0.113.30",
      ingressFamily: "ipv4",
      name: "Fixed Pooled",
      port: 24000,
      ipv4Port: 0,
      enabled: true,
      hideNative: true,
      udp: true,
      state: "verified",
    };
    const payload = buildRouteChangePayload(route, { enabled: false, expectedRevision: "7" });
    expect(payload).toEqual({
      id: "route-pooled",
      accountId: "acct-1",
      entryId: "entry-a",
      egressId: "landing-fixed",
      relayPoolId: "pool-east",
      udp: true,
      hideNative: true,
      enabled: false,
      expectedRevision: "7",
    });
    expect("activeRelays" in payload).toBe(false);
    expect("activeRelayIds" in payload).toBe(false);
    expect("state" in payload).toBe(false);
    expect("port" in payload).toBe(false);
    expect("retiringLegacyTransport" in payload).toBe(false);
    expect(buildRouteChangePayload(route, { udp: false, expectedRevision: "7" }).udp).toBe(false);
  });

  it("aligns identifier and display-name validation with Go model.go contract", () => {
    // Go ValidIdentifier: 1..128 ASCII [A-Za-z0-9_-], no dots, leading - or _ allowed
    expect(isValidIdentifier("_pool-1")).toBe(true);
    expect(isValidIdentifier("-leading-dash")).toBe(true);
    expect(isValidIdentifier("a".repeat(128))).toBe(true);
    expect(isValidIdentifier("a".repeat(129))).toBe(false);
    expect(isValidIdentifier("pool.with.dot")).toBe(false);
    expect(isValidIdentifier("")).toBe(false);

    // Go validDisplayName: non-empty trimmed, <= 512 runes, no CR/LF/NUL
    expect(isValidDisplayName("东".repeat(80))).toBe(true);
    expect(isValidDisplayName("a".repeat(512))).toBe(true);
    expect(isValidDisplayName("a".repeat(513))).toBe(false);
    expect(isValidDisplayName("bad\nname")).toBe(false);

    expect(validatePoolDraft({ id: "pool.dot", name: "Pool", strategy: { expected: 1, maxRttMs: 500 }, members: [] })).not.toBe("");
    expect(validatePoolDraft({ id: "_existing-pool_128", name: "东".repeat(80), strategy: { expected: 1, maxRttMs: 500 }, members: [] })).toBe("");
  });

  it("omits drain metadata when undrained and preserves RFC3339 drain fields when drained", () => {
    const payload = buildRelayPoolChangePayload({
      id: "pool-east",
      name: "East Pool",
      revision: "3",
      expectedRevision: "3",
      strategy: { expected: 2, maxRttMs: 500, tolerance: 0.05 },
      members: [
        {
          nodeId: "relay-1",
          certificateId: "a".repeat(64),
          ingressIpv4: "198.51.100.11",
          egressIpv4: "198.51.100.11",
          drained: false,
          drainReason: "stale reason",
          drainResumeAt: "0001-01-01T00:00:00Z",
          nodeSuspended: false,
          runtimeReady: true,
        },
        {
          nodeId: "relay-2",
          certificateId: "b".repeat(64),
          ingressIpv4: "198.51.100.12",
          egressIpv4: "198.51.100.12",
          drained: true,
          drainReason: "maintenance",
          drainResumeAt: "2026-12-01T00:00:00Z",
          nodeSuspended: false,
          runtimeReady: false,
        },
      ],
    }) as { pool: { members: Record<string, unknown>[] } };
    expect(payload.pool.members[0]).toEqual({
      nodeId: "relay-1",
      certificateId: "a".repeat(64),
      ingressIpv4: "198.51.100.11",
      egressIpv4: "198.51.100.11",
    });
    expect(payload.pool.members[1]).toEqual({
      nodeId: "relay-2",
      certificateId: "b".repeat(64),
      ingressIpv4: "198.51.100.12",
      egressIpv4: "198.51.100.12",
      drained: true,
      drainReason: "maintenance",
      drainResumeAt: "2026-12-01T00:00:00Z",
    });
  });

  it("enforces intervalSec >= 10, strategy expected >= 1, and includes expectedConfigRevision CAS token", () => {
    expect(validateObservatoryDraft({ destination: "https://www.gstatic.com/generate_204", intervalSec: 9, sampling: 3, timeoutSec: 5 })).not.toBe("");
    expect(validateObservatoryDraft({ destination: "https://www.gstatic.com/generate_204", intervalSec: 15, sampling: 3, timeoutSec: 20 })).not.toBe("");
    expect(validateObservatoryDraft({ destination: "https://www.gstatic.com/generate_204", intervalSec: 15, sampling: 3, timeoutSec: 5 })).toBe("");
    expect(validatePoolDraft({ id: "pool-1", name: "Pool 1", strategy: { expected: 0, maxRttMs: 500 }, members: [] })).not.toBe("");
    expect(validatePoolDraft({ id: "pool-1", name: "Pool 1", strategy: { expected: 1, maxRttMs: 500 }, members: [] })).toBe("");
    expect(
      buildEntryRelayConfigPayload("entry-a", "5", "2", {
        revision: "2",
        sourceIpv4: "198.51.100.2",
        observatory: { destination: "https://www.gstatic.com/generate_204", intervalSec: 15, sampling: 3, timeoutSec: 5 },
      }),
    ).toEqual({
      entryId: "entry-a",
      expectedRevision: "5",
      expectedConfigRevision: "2",
      config: {
        sourceIpv4: "198.51.100.2",
        observatory: { destination: "https://www.gstatic.com/generate_204", intervalSec: 15, sampling: 3, timeoutSec: 5 },
      },
    });
  });

  it("gates socket cutover start strictly on completed current-revision inspect with scopeDigest, migratable consumers, and zero blockers", () => {
    const validPlan: SocketCutoverPlan = {
      targetNodeId: "landing-1",
      address: "198.51.100.30",
      port: 24000,
      occupied: true,
      deferred: false,
      scopeDigest: "a".repeat(64),
      blockingConsumers: [],
      consumers: [{ kind: "two-hop-source", entryId: "entry-a", entryCertificateId: "a".repeat(64), source: "198.51.100.2" }],
    };
    expect(canStartSocketCutover(undefined, "4").allowed).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: true }, "4").allowed).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: false, failed: "timeout" }, "4").allowed).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: false, plan: { ...validPlan, scopeDigest: undefined }, inspectedRevision: "4" }, "4").allowed).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: false, plan: validPlan, inspectedRevision: "3" }, "4").allowed).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: false, plan: { ...validPlan, occupied: false }, inspectedRevision: "4" }, "4").allowed).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: false, plan: { ...validPlan, deferred: true, blockingConsumers: ["entry-a"] }, inspectedRevision: "4" }, "4").allowed).toBe(false);
    expect(
      canStartSocketCutover(
        { seq: 1, pending: false, plan: { ...validPlan, consumers: [{ kind: "pooled-route-landing", entryId: "entry-a", entryCertificateId: "a".repeat(64) }] }, inspectedRevision: "4" },
        "4",
      ).allowed,
    ).toBe(false);
    expect(canStartSocketCutover({ seq: 1, pending: false, plan: validPlan, inspectedRevision: "4" }, "4")).toEqual({ allowed: true, reason: "", migratableCount: 1 });
  });
});

describe("observatory evaluation and three-column topology model", () => {
  it("distinguishes healthy, unhealthy, stale, and no-sample states accurately", () => {
    const now = Date.parse("2026-11-28T12:00:00Z");
    const configs = {
      "entry-a": { observatory: { destination: "https://www.gstatic.com/generate_204", intervalSec: 20, sampling: 3, timeoutSec: 5 } },
    };
    const fresh = evaluateObservatorySample(
      { entryId: "entry-a", poolId: "p", relayNodeId: "r1", egressId: "l1", outboundTag: "t1", alive: true, delayMs: 42, sampledAt: new Date(now - 10_000).toISOString() },
      "entry-a",
      configs,
      now,
    );
    expect(fresh.state).toBe("healthy");
    expect(fresh.delayMs).toBe(42);

    const stale = evaluateObservatorySample(
      { entryId: "entry-a", poolId: "p", relayNodeId: "r1", egressId: "l1", outboundTag: "t1", alive: true, delayMs: 42, sampledAt: new Date(now - 90_000).toISOString() },
      "entry-a",
      configs,
      now,
    );
    expect(stale.state).toBe("stale");
    expect(stale.stale).toBe(true);

    const failed = evaluateObservatorySample(
      { entryId: "entry-a", poolId: "p", relayNodeId: "r1", egressId: "l1", outboundTag: "t1", alive: false, delayMs: 0, lastErrorReason: "context deadline exceeded", sampledAt: new Date(now - 5_000).toISOString() },
      "entry-a",
      configs,
      now,
    );
    expect(failed.state).toBe("unhealthy");
    expect(failed.lastErrorReason).toBe("context deadline exceeded");

    const none = evaluateObservatorySample(undefined, "entry-a", configs, now);
    expect(none.state).toBe("no-sample");
  });

  it("separates pending legacy three-hop from two-hop before cutover and transitions to pooled after cutover", () => {
    const now = Date.parse("2026-11-28T12:00:00Z");
    const base = sampleInventory(now);
    const names = new Map(base.nodes.map((n) => [n.id, n.name]));
    const legacyRoute: Route = {
      id: "route-legacy-3hop",
      accountId: "acct-1",
      entryId: "entry-a",
      egressId: "landing-fixed",
      relayId: "relay-1",
      pendingRelayPoolId: "pool-east",
      pendingLegacyCutover: true,
      port: 24000,
      enabled: true,
      hideNative: false,
      state: "verified",
    };

    expect(routeTopologyKind(legacyRoute)).toBe("legacy-three-hop");
    const preInv: Inventory = { ...base, routes: [base.routes[0], legacyRoute] };
    const preAll = buildTopologyModel({ inventory: preInv, names, latencies: new Map(), now, latencyFailed: false, filter: "all" });
    expect(preAll.twoHopEdges).toHaveLength(1);
    expect(preAll.twoHopEdges[0].route.id).toBe("route-twohop");
    expect(preAll.legacyRelays).toHaveLength(1);
    expect(preAll.legacyRelays[0].pendingPoolIds).toEqual(["pool-east"]);
    expect(preAll.legacyEdges).toHaveLength(1);
    expect(preAll.entries[0].twoHopRouteCount).toBe(1);
    expect(preAll.entries[0].legacyThreeHopCount).toBe(1);
    expect(isLegacyEdgeSelectedOrConnected({ kind: "pool", id: "pool-east" }, preAll.legacyEdges[0])).toBe(true);

    // Filter "two-hop" strictly excludes pending legacy three-hop
    const preTwoHopOnly = buildTopologyModel({ inventory: preInv, names, latencies: new Map(), now, latencyFailed: false, filter: "two-hop" });
    expect(preTwoHopOnly.twoHopEdges).toHaveLength(1);
    expect(preTwoHopOnly.legacyEdges).toHaveLength(0);
    expect(preTwoHopOnly.legacyRelays).toHaveLength(0);

    // Post-cutover: route switches to relayPoolId and leaves legacyRelays/legacyEdges empty
    const postRoute: Route = {
      ...legacyRoute,
      relayId: undefined,
      pendingRelayPoolId: undefined,
      pendingLegacyCutover: false,
      relayPoolId: "pool-east",
      activeRelays: 1,
      activeRelayIds: ["relay-1"],
    };
    const postInv: Inventory = { ...base, routes: [base.routes[0], postRoute] };
    const postAll = buildTopologyModel({ inventory: postInv, names, latencies: new Map(), now, latencyFailed: false, filter: "all" });
    expect(postAll.legacyRelays).toHaveLength(0);
    expect(postAll.legacyEdges).toHaveLength(0);
    expect(postAll.entryPoolEdges).toHaveLength(1);
    expect(postAll.poolLandingEdges).toHaveLength(2);
  });

  it("keeps multi-row two-hop segmented bridge lanes strictly inside the top corridor above every pool card", () => {
    const now = Date.parse("2026-11-28T12:00:00Z");
    const inv: Inventory = {
      state: "owned",
      accounts: [],
      endpoints: [],
      nodes: [
        { id: "e1", name: "Entry 1" },
        { id: "e2", name: "Entry 2" },
        { id: "e3", name: "Entry 3" },
        { id: "e4", name: "Entry 4" },
        { id: "r1", name: "Relay 1" },
        { id: "l1", name: "Landing 1" },
        { id: "l2", name: "Landing 2" },
        { id: "l3", name: "Landing 3" },
        { id: "l4", name: "Landing 4" },
      ],
      runtimes: [
        ...["e1", "e2", "e3", "e4"].map((id) => ({ id, role: "entry", revision: "1", runtimeReady: true, reportedAt: "", peers: [] })),
        ...["r1", "l1", "l2", "l3", "l4"].map((id) => ({ id, certificateId: "a".repeat(64), role: "landing", revision: "1", runtimeReady: true, reportedAt: "", peers: [] })),
      ],
      relayPools: [
        {
          id: "pool-1",
          name: "Pool 1",
          revision: "1",
          strategy: { expected: 1, maxRttMs: 500 },
          members: [{ nodeId: "r1", certificateId: "a".repeat(64), ingressIpv4: "198.51.100.11", egressIpv4: "198.51.100.11", drained: false, nodeSuspended: false, runtimeReady: true }],
          routeIds: [],
        },
        {
          id: "pool-2",
          name: "Pool 2",
          revision: "1",
          strategy: { expected: 1, maxRttMs: 500 },
          members: [{ nodeId: "r1", certificateId: "a".repeat(64), ingressIpv4: "198.51.100.11", egressIpv4: "198.51.100.11", drained: false, nodeSuspended: false, runtimeReady: true }],
          routeIds: [],
        },
      ],
      routes: [
        { id: "rt1", accountId: "a1", entryId: "e1", egressId: "l1", port: 1080, enabled: true, hideNative: false, state: "verified" },
        { id: "rt2", accountId: "a1", entryId: "e2", egressId: "l2", port: 1080, enabled: true, hideNative: false, state: "verified" },
        { id: "rt3", accountId: "a1", entryId: "e3", egressId: "l3", port: 1080, enabled: true, hideNative: false, state: "verified" },
        { id: "rt4", accountId: "a1", entryId: "e4", egressId: "l4", port: 1080, enabled: true, hideNative: false, state: "verified" },
      ],
    };
    const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
    const model = buildTopologyModel({ inventory: inv, names, latencies: new Map(), now, latencyFailed: false, filter: "all" });
    const minPoolY = Math.min(...model.pools.map((p) => p.y));
    const minPoolX = Math.min(...model.pools.map((p) => p.x));
    const maxPoolRightX = Math.max(...model.pools.map((p) => p.x + p.width));

    expect(model.twoHopEdges).toHaveLength(4);
    for (const edge of model.twoHopEdges) {
      expect(edge.corridorY).toBeLessThan(minPoolY);
      expect(edge.corridorLeftX).toBeLessThan(minPoolX);
      expect(edge.corridorRightX).toBeGreaterThan(maxPoolRightX);
      expect(edge.d).toContain(`L ${edge.corridorRightX} ${edge.corridorY}`);
    }
  });

  it("builds 3-column topology separating two-hop direct bridges from three-hop pooled paths", () => {
    const now = Date.parse("2026-11-28T12:00:00Z");
    const inv = sampleInventory(now);
    const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
    const latencies = new Map<string, RouteLatency>([
      [latencyKey("entry-a", "landing-direct", 1080), { entryId: "entry-a", landingId: "landing-direct", port: 1080, state: "ready", latencyMs: 24, samples: 3, checkedAt: new Date(now - 5_000).toISOString() }],
    ]);

    const summary = summarizePooledRoute(inv.routes[1], inv, now);
    expect(summary.admittedCount).toBe(1);
    expect(summary.healthyCount).toBe(1);
    expect(summary.bestDelayMs).toBe(38);
    expect(summary.blockedByEmptyPool).toBe(false);

    const model = buildTopologyModel({ inventory: inv, names, latencies, now, latencyFailed: false, filter: "all" });
    expect(model.entries).toHaveLength(1);
    expect(model.pools).toHaveLength(1);
    expect(model.pools[0].members).toHaveLength(2);
    expect(model.landings.map((l) => l.id).sort()).toEqual(["landing-direct", "landing-fixed"]);
    expect(model.twoHopEdges).toHaveLength(1);
    expect(model.entryPoolEdges).toHaveLength(1);
    expect(model.poolLandingEdges).toHaveLength(2);

    const memberSelection = { kind: "member" as const, poolId: "pool-east", nodeId: "relay-1" };
    expect(isPathSelectedOrConnected(memberSelection, model.poolLandingEdges[0].path)).toBe(true);
    expect(isPathSelectedOrConnected(memberSelection, model.poolLandingEdges[1].path)).toBe(false);
    expect(isTwoHopSelectedOrConnected(memberSelection, model.twoHopEdges[0])).toBe(false);
    expect(isEntryPoolSelectedOrConnected(memberSelection, model.entryPoolEdges[0], model.allFullPaths)).toBe(true);
  });
});
