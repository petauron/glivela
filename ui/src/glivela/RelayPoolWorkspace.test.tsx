// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { latencyKey, type RouteLatency } from "./RouteLatency";
import type { Inventory, SocketCutoverPlan } from "./control-types";
import { GlivelaControl } from "./Control";
import { RelayPoolWorkspace } from "./RelayPoolWorkspace";
import { RouteWorkspace } from "./RouteWorkspace";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

function fixtureInventory(now: number): Inventory {
  return {
    state: "owned",
    accounts: [
      {
        account: { id: "acct-1", displayName: "Primary", desiredRevision: "9", plan: { totalBytes: "0", expiryTime: "0", resetDays: 0, enabled: true } },
        usage: [],
        schedule: { nextResetAt: "" },
        traffic: {},
      },
    ],
    endpoints: [{ id: "ep-1", entryId: "entry-a", nodeId: "entry-a", name: "Entry A", retired: false }],
    nodes: [
      { id: "entry-a", name: "Entry Alpha" },
      { id: "entry-old", name: "Entry Legacy" },
      { id: "relay-1", name: "Relay One" },
      { id: "relay-2", name: "Relay Offline" },
      { id: "landing-twohop", name: "Direct Exit" },
      { id: "landing-pooled", name: "Fixed Exit" },
    ],
    runtimes: [
      { id: "entry-a", role: "entry", revision: "5", appliedRevision: "5", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.2", reportedAt: new Date(now - 5_000).toISOString(), peers: ["landing-twohop"] },
      { id: "entry-old", role: "entry", revision: "2", appliedRevision: "2", runtimeReady: true, relayPoolCapable: false, publicIpv4: "198.51.100.3", reportedAt: new Date(now - 5_000).toISOString(), peers: ["landing-twohop"] },
      { id: "relay-1", certificateId: "a".repeat(64), role: "landing", revision: "4", appliedRevision: "4", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.11", egressIp: "198.51.100.11", reportedAt: new Date(now - 5_000).toISOString(), peers: [] },
      { id: "relay-2", certificateId: "b".repeat(64), role: "landing", revision: "4", appliedRevision: "2", runtimeReady: false, relayPoolCapable: true, publicIpv4: "198.51.100.12", egressIp: "198.51.100.12", reportedAt: new Date(now - 300_000).toISOString(), peers: [] },
      { id: "landing-twohop", certificateId: "c".repeat(64), role: "landing", revision: "3", appliedRevision: "3", runtimeReady: true, publicIpv4: "198.51.100.20", egressIp: "203.0.113.20", occupiedPort24000: ["198.51.100.20"], reportedAt: new Date(now - 5_000).toISOString(), peers: [] },
      { id: "landing-pooled", certificateId: "d".repeat(64), role: "landing", revision: "6", appliedRevision: "6", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.30", publicIpv6: "2001:db8::30", egressIp: "203.0.113.30", reportedAt: new Date(now - 5_000).toISOString(), peers: [] },
    ],
    relayPools: [
      {
        id: "pool-ap",
        name: "AP Pool",
        revision: "3",
        strategy: { expected: 2, maxRttMs: 450, tolerance: 0.05 },
        members: [
          { nodeId: "relay-1", certificateId: "a".repeat(64), ingressIpv4: "198.51.100.11", egressIpv4: "198.51.100.11", drained: false, nodeSuspended: false, runtimeReady: true },
          { nodeId: "relay-2", certificateId: "b".repeat(64), ingressIpv4: "198.51.100.12", egressIpv4: "198.51.100.12", drained: false, nodeSuspended: false, runtimeReady: false },
        ],
        routeIds: ["route-pooled"],
        revocation: { pendingEntries: ["entry-a"], pendingLandings: [], complete: false },
      },
    ],
    entryRelayConfigs: {
      "entry-a": {
        revision: "1",
        sourceIpv4: "198.51.100.2",
        observatory: { destination: "https://www.gstatic.com/generate_204", intervalSec: 15, sampling: 3, timeoutSec: 5 },
      },
    },
    observatoryPaths: [
      {
        entryId: "entry-a",
        grantId: "route-pooled",
        poolId: "pool-ap",
        relayNodeId: "relay-1",
        egressId: "landing-pooled",
        outboundTag: "pool-0-0",
        alive: true,
        delayMs: 36,
        averageMs: 39,
        minMs: 33,
        maxMs: 45,
        allSamples: 3,
        failedSamples: 0,
        sampledAt: new Date(now - 8_000).toISOString(),
      },
    ],
    routes: [
      { id: "route-direct", accountId: "acct-1", entryId: "entry-a", egressId: "landing-twohop", port: 1080, enabled: true, hideNative: false, state: "verified" },
      {
        id: "route-pooled",
        accountId: "acct-1",
        entryId: "entry-a",
        egressId: "landing-pooled",
        relayPoolId: "pool-ap",
        activeRelays: 1,
        activeRelayIds: ["relay-1"],
        landingAddress: "198.51.100.30",
        egressIp: "203.0.113.30",
        port: 24000,
        enabled: true,
        hideNative: false,
        state: "verified",
      },
      {
        id: "route-legacy-3hop",
        accountId: "acct-1",
        entryId: "entry-a",
        egressId: "landing-pooled",
        relayId: "relay-1",
        pendingRelayPoolId: "pool-ap",
        pendingLegacyCutover: true,
        port: 24000,
        enabled: true,
        hideNative: false,
        state: "verified",
      },
    ],
  };
}

it("renders interactive SVG topology with group role, aria-pressed keyboard controls, legacy 3-hop separation, and pool mutations", async () => {
  const now = Date.parse("2026-11-28T12:00:00Z");
  const inv = fixtureInventory(now);
  const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
  const latencies = new Map<string, RouteLatency>([
    [latencyKey("entry-a", "landing-twohop", 1080), { entryId: "entry-a", landingId: "landing-twohop", port: 1080, state: "ready", latencyMs: 22, samples: 3, checkedAt: new Date(now - 4_000).toISOString() }],
  ]);
  const save = vi.fn(async () => true);

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  try {
    await act(async () => {
      root.render(
        <RelayPoolWorkspace
          inventory={inv}
          names={names}
          disabled={false}
          save={save}
          latency={{ values: latencies, now, error: "" }}
        />,
      );
    });

    // SVG uses role="group" (not static role="img"), distinguishes legacy three-hop from two-hop direct
    const svg = div.querySelector("svg.gl-topology-svg");
    expect(svg).not.toBeNull();
    expect(svg?.getAttribute("role")).toBe("group");
    expect(svg?.textContent).toContain("Entry Alpha");
    expect(svg?.textContent).toContain("AP Pool");
    expect(svg?.textContent).toContain("Direct Exit");
    expect(svg?.textContent).toContain("Fixed Exit");
    expect(svg?.querySelector("rect.gl-topo-pool-box")?.getAttribute("stroke-dasharray")).toBe("6 4");
    expect(svg?.querySelectorAll('[data-edge-kind="two-hop"]')).toHaveLength(1);
    expect(svg?.querySelectorAll('[data-edge-kind="legacy-three-hop"]')).toHaveLength(1);
    expect(svg?.querySelectorAll('[data-node-kind="legacy-relay"]')).toHaveLength(1);
    expect(svg?.querySelectorAll('[data-edge-kind="entry-pool"]')).toHaveLength(1);
    expect(svg?.querySelectorAll('[data-edge-kind="pool-landing"]')).toHaveLength(2);
    expect(div.querySelector("a")).toBeNull();

    // Keyboard Enter and Space toggle aria-pressed and selection on SVG member button
    const memberPill = svg?.querySelector('.gl-topo-member-pill[aria-label*="Relay One"]') as SVGGElement;
    expect(memberPill).not.toBeNull();
    expect(memberPill.getAttribute("aria-pressed")).toBe("false");
    await act(async () => {
      memberPill.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });
    expect(memberPill.getAttribute("aria-pressed")).toBe("true");
    expect(memberPill.getAttribute("data-selected")).toBe("true");
    expect(div.textContent).toContain("36ms");
    expect(div.textContent).toContain("期望配置");
    expect(div.textContent).toContain("节点回执");

    // Path table offers a native keyboard-accessible toggle button with aria-pressed
    const pathButton = div.querySelector(".gl-topo-path-table button.gl-route-name") as HTMLButtonElement;
    expect(pathButton).not.toBeNull();
    expect(pathButton.getAttribute("aria-pressed")).toBe("false");
    await act(async () => {
      pathButton.click();
    });
    expect(pathButton.getAttribute("aria-pressed")).toBe("true");

    // Space key toggles SVG button back off cleanly
    await act(async () => {
      memberPill.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    });
    expect(memberPill.getAttribute("aria-pressed")).toBe("true");
    await act(async () => {
      memberPill.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    });
    expect(memberPill.getAttribute("aria-pressed")).toBe("false");

    // Reorder member (#1 Relay One move down)
    const moveDownBtn = div.querySelector('button[aria-label="下移 AP Pool 成员 Relay One"]') as HTMLButtonElement;
    await act(async () => {
      moveDownBtn.click();
    });
    expect(save).toHaveBeenLastCalledWith(
      "relay-pools",
      expect.objectContaining({
        expectedRevision: "3",
        pool: expect.objectContaining({
          id: "pool-ap",
          members: [expect.objectContaining({ nodeId: "relay-2" }), expect.objectContaining({ nodeId: "relay-1" })],
        }),
      }),
    );

    // Member-level drain (independent of node suspension) submits drained: true with reason
    const drainBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "排空") as HTMLButtonElement;
    await act(async () => {
      drainBtn.click();
    });
    const reasonInput = div.querySelector('input[placeholder*="路由维护"]') as HTMLInputElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    await act(async () => {
      valueSetter?.call(reasonInput, "scheduled relay maintenance");
      reasonInput.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const confirmDrainBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "确认排空") as HTMLButtonElement;
    await act(async () => {
      confirmDrainBtn.click();
    });
    expect(save).toHaveBeenLastCalledWith(
      "relay-pools",
      expect.objectContaining({
        expectedRevision: "3",
        pool: expect.objectContaining({
          id: "pool-ap",
          members: expect.arrayContaining([
            expect.objectContaining({ nodeId: "relay-1", drained: true, drainReason: "scheduled relay maintenance" }),
          ]),
        }),
      }),
    );

    // Offline member immediate removal succeeds without waiting for offline relay-2
    const offlineRemoveBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "离线摘除") as HTMLButtonElement;
    await act(async () => {
      offlineRemoveBtn.click();
    });
    const confirmRemoveBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "确认摘除") as HTMLButtonElement;
    await act(async () => {
      confirmRemoveBtn.click();
    });
    expect(save).toHaveBeenLastCalledWith(
      "relay-pools",
      expect.objectContaining({
        expectedRevision: "3",
        pool: expect.objectContaining({
          id: "pool-ap",
          members: [expect.objectContaining({ nodeId: "relay-1" })],
        }),
      }),
    );
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});

it("requires current-revision inspect with scopeDigest, invalidates on in-flight/failed re-inspect, and drops stale out-of-order inspects", async () => {
  const now = Date.parse("2026-11-28T12:00:00Z");
  const inv = fixtureInventory(now);
  const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
  const save = vi.fn(async () => true);

  const digest1 = "a".repeat(64);
  const digest2 = "b".repeat(64);
  const basePlan: SocketCutoverPlan = {
    targetNodeId: "landing-twohop",
    address: "198.51.100.20",
    port: 24000,
    occupied: true,
    deferred: true,
    scopeDigest: digest1,
    blockingConsumers: ["entry-a"],
    consumers: [{ kind: "two-hop-source", entryId: "entry-a", entryCertificateId: "a".repeat(64), source: "198.51.100.2" }],
  };
  let nextFetch: (init?: RequestInit) => Promise<Response> = async () =>
    new Response(JSON.stringify(basePlan), { headers: { "Content-Type": "application/json" } });
  vi.stubGlobal(
    "fetch",
    vi.fn((_url: string, init?: RequestInit) => nextFetch(init)),
  );

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  const render = (currentInv: Inventory) =>
    root.render(
      <RelayPoolWorkspace
        inventory={currentInv}
        names={names}
        disabled={false}
        save={save}
        latency={{ values: new Map(), now, error: "" }}
      />,
    );

  try {
    await act(async () => render(inv));
    const cutoverTab = [...div.querySelectorAll("button")].find((b) => b.textContent?.includes("端口 24000 切窗与迁移")) as HTMLButtonElement;
    await act(async () => cutoverTab.click());

    const startBtn = () => [...div.querySelectorAll("button")].find((b) => b.textContent === "开启 24000 切窗") as HTMLButtonElement;
    const inspectBtn = () => [...div.querySelectorAll("button")].find((b) => b.textContent === "检查占用与影响范围") as HTMLButtonElement;
    expect(startBtn().disabled).toBe(true);

    // 1. Blocked inspect keeps Start disabled and shows blocker + consumer details
    await act(async () => inspectBtn().click());
    expect(startBtn().disabled).toBe(true);
    expect(div.textContent).toContain("阻塞节点：Entry Alpha");
    expect(div.textContent).toContain("两跳共享监听源授权");

    // 2. Clean inspect enables Start, shows separate migration scope & worker-restart impact, and sends expectedScopeDigest
    nextFetch = async () =>
      new Response(JSON.stringify({ ...basePlan, deferred: false, blockingConsumers: [], scopeDigest: digest1 }), {
        headers: { "Content-Type": "application/json" },
      });
    await act(async () => inspectBtn().click());
    expect(startBtn().disabled).toBe(false);
    expect(div.textContent).toContain("切窗迁移范围");
    expect(div.textContent).toContain("进程重启影响");
    await act(async () => startBtn().click());
    expect(save).toHaveBeenCalledWith("socket-cutover", {
      action: "start",
      targetNodeId: "landing-twohop",
      address: "198.51.100.20",
      expectedTargetRevision: "3",
      expectedScopeDigest: digest1,
    });

    // 2b. If Start is rejected by backend (e.g. scope changed), invalidate stale preview and force re-inspect
    save.mockResolvedValueOnce(false);
    await act(async () => startBtn().click());
    expect(startBtn().disabled).toBe(true);
    expect(div.textContent).toContain("重新检查占用与影响范围");
    await act(async () => inspectBtn().click());
    expect(startBtn().disabled).toBe(false);

    // 3. Re-inspect in-flight immediately disables Start; a newer inspect supersedes the older slow inspect
    let resolveSlow: ((res: Response) => void) | undefined;
    nextFetch = () => new Promise<Response>((resolve) => { resolveSlow = resolve; });
    await act(async () => { inspectBtn().click(); });
    expect(startBtn().disabled).toBe(true);

    // Trigger newer inspect returning digest2 before slow inspect resolves
    nextFetch = async () =>
      new Response(JSON.stringify({ ...basePlan, deferred: false, blockingConsumers: [], scopeDigest: digest2 }), {
        headers: { "Content-Type": "application/json" },
      });
    await act(async () => inspectBtn().click());
    expect(startBtn().disabled).toBe(false);

    // Older slow inspect finally settles with digest1 -> MUST NOT overwrite digest2!
    resolveSlow?.(
      new Response(JSON.stringify({ ...basePlan, deferred: false, blockingConsumers: [], scopeDigest: digest1 }), {
        headers: { "Content-Type": "application/json" },
      }),
    );
    await act(async () => {});
    await act(async () => startBtn().click());
    expect(save).toHaveBeenLastCalledWith("socket-cutover", {
      action: "start",
      targetNodeId: "landing-twohop",
      address: "198.51.100.20",
      expectedTargetRevision: "3",
      expectedScopeDigest: digest2,
    });

    // 4. Failed re-inspect clears prior preview and keeps Start disabled
    nextFetch = async () => new Response("unavailable", { status: 503 });
    await act(async () => inspectBtn().click());
    expect(startBtn().disabled).toBe(true);

    // 5. Explicit legacy three-hop cutover action still works
    const legacyBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "切换至中转池") as HTMLButtonElement;
    await act(async () => legacyBtn.click());
    expect(save).toHaveBeenLastCalledWith("socket-cutover", { action: "cutover-legacy", grantId: "route-legacy-3hop" });
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});

it("preserves unsaved EntryObservatoryEditor draft when background polling advances config revision", async () => {
  const now = Date.parse("2026-11-28T12:00:00Z");
  const inv = fixtureInventory(now);
  const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
  const save = vi.fn(async () => false);

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  const render = (currentInv: Inventory) =>
    root.render(
      <RelayPoolWorkspace
        inventory={currentInv}
        names={names}
        disabled={false}
        save={save}
        latency={{ values: new Map(), now, error: "" }}
      />,
    );

  try {
    await act(async () => render(inv));
    const obsTab = [...div.querySelectorAll("button")].find((b) => b.textContent?.includes("入口探测与源地址")) as HTMLButtonElement;
    await act(async () => obsTab.click());
    const editBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "编辑配置") as HTMLButtonElement;
    await act(async () => editBtn.click());

    // Edit sourceIpv4 in the open Sheet (rendered in portal inside document.body)
    const src4Input = [...document.querySelectorAll("input")].find((el) => el.value === "198.51.100.2") as HTMLInputElement;
    expect(src4Input).toBeDefined();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    await act(async () => {
      setter?.call(src4Input, "203.0.113.88");
      src4Input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(src4Input.value).toBe("203.0.113.88");

    // Simulate background poll advancing entryRelayConfigs["entry-a"].revision to "2" with another IP
    const polledInv: Inventory = {
      ...inv,
      entryRelayConfigs: {
        "entry-a": {
          revision: "2",
          sourceIpv4: "198.51.100.99",
          observatory: { destination: "https://www.gstatic.com/generate_204", intervalSec: 25, sampling: 3, timeoutSec: 5 },
        },
      },
    };
    await act(async () => render(polledInv));

    // Draft input is preserved (NOT remounted), external-change banner is shown
    expect(src4Input.value).toBe("203.0.113.88");
    expect(document.body.textContent).toContain("检测到外部配置或节点修订已更新");

    // Submitting without reload preserves original CAS baseline expectedConfigRevision="1"
    const submitBtn = [...document.querySelectorAll('button[type="submit"]')].find((b) => b.textContent === "保存入口探测与源地址配置") as HTMLButtonElement;
    await act(async () => submitBtn.click());
    expect(save).toHaveBeenLastCalledWith(
      "entry-observatory",
      expect.objectContaining({
        entryId: "entry-a",
        expectedRevision: "5",
        expectedConfigRevision: "1",
        config: expect.objectContaining({ sourceIpv4: "203.0.113.88" }),
      }),
    );

    // Explicitly clicking "重新加载最新配置" refreshes draft & CAS baseline to rev "2"
    const reloadBtn = [...document.querySelectorAll("button")].find((b) => b.textContent === "重新加载最新配置") as HTMLButtonElement;
    await act(async () => reloadBtn.click());
    expect(src4Input.value).toBe("198.51.100.99");
    await act(async () => submitBtn.click());
    expect(save).toHaveBeenLastCalledWith(
      "entry-observatory",
      expect.objectContaining({
        expectedConfigRevision: "2",
        config: expect.objectContaining({ sourceIpv4: "198.51.100.99" }),
      }),
    );
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});

it("opens existing pool with id='new' in edit mode instead of colliding with create sentinel", async () => {
  const now = Date.parse("2026-11-28T12:00:00Z");
  const inv = fixtureInventory(now);
  inv.relayPools = [
    {
      ...inv.relayPools![0],
      id: "new",
      name: "Existing Pool Named New",
    },
  ];
  inv.routes = inv.routes.map((r) => (r.relayPoolId === "pool-ap" ? { ...r, relayPoolId: "new" } : r));
  const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
  const save = vi.fn(async () => true);

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  try {
    await act(async () => {
      root.render(
        <RelayPoolWorkspace
          inventory={inv}
          names={names}
          disabled={false}
          save={save}
          latency={{ values: new Map(), now, error: "" }}
        />,
      );
    });
    const editPoolBtn = [...div.querySelectorAll("button")].find((b) => b.textContent?.includes("编辑池")) as HTMLButtonElement;
    await act(async () => editPoolBtn.click());
    expect(document.body.textContent).toContain("编辑中转池 · Existing Pool Named New");
    const idInput = [...document.querySelectorAll("input")].find((el) => el.value === "new") as HTMLInputElement;
    expect(idInput).toBeDefined();
    expect(idInput.readOnly).toBe(true);

    // Close edit sheet and verify SVG pool selection -> "编辑中转池" also opens edit mode for id="new"
    const closeBtn = [...document.querySelectorAll("button")].find((b) => b.textContent?.includes("Close")) as HTMLButtonElement | undefined;
    if (closeBtn) {
      await act(async () => closeBtn.click());
    }
    const svgPoolGroup = div.querySelector('svg g[role="button"][aria-label*="Existing Pool Named New"]') as SVGGElement;
    expect(svgPoolGroup).not.toBeNull();
    await act(async () => {
      svgPoolGroup.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    const svgEditBtn = [...div.querySelectorAll("button")].find((b) => b.textContent?.trim() === "编辑中转池") as HTMLButtonElement;
    expect(svgEditBtn).toBeDefined();
    await act(async () => svgEditBtn.click());
    expect(document.body.textContent).toContain("编辑中转池 · Existing Pool Named New");
    const svgIdInput = [...document.querySelectorAll("input")].find((el) => el.value === "new") as HTMLInputElement;
    expect(svgIdInput).toBeDefined();
    expect(svgIdInput.readOnly).toBe(true);
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});

it("prevents an older out-of-order refresh() from overwriting a newer pools background poll()", async () => {
  vi.useFakeTimers();
  const baseNow = Date.parse("2026-11-28T12:00:00Z");
  vi.setSystemTime(baseNow);
  Object.defineProperty(document, "hidden", { configurable: true, value: false });

  const inv1 = fixtureInventory(baseNow);
  let businessCall = 0;
  let resolveOldRefresh: ((res: Response) => void) | undefined;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.endsWith("/ip-quality")) return new Response(JSON.stringify({ targets: [], checks: [] }), { headers: { "Content-Type": "application/json" } });
      if (url.endsWith("/route-latencies")) return new Response(JSON.stringify({ latencies: [] }), { headers: { "Content-Type": "application/json" } });
      if (url.endsWith("/network-optimization")) return new Response(JSON.stringify({ nodes: [] }), { headers: { "Content-Type": "application/json" } });
      if (url.endsWith("/link-speeds")) return new Response(JSON.stringify({ revision: "0", tests: [], channels: [] }), { headers: { "Content-Type": "application/json" } });
      if (url.endsWith("/node-egress")) {
        return new Response(
          JSON.stringify({ id: "landing-twohop", role: "landing", revision: "3", runtimeReady: true, egressIp: "203.0.113.20", linkedEntries: 0 }),
          { headers: { "Content-Type": "application/json" } },
        );
      }
      if (url.endsWith("/business")) {
        businessCall += 1;
        if (businessCall === 1) {
          return new Response(JSON.stringify(inv1), { headers: { "Content-Type": "application/json" } });
        }
        if (businessCall === 2) {
          // Triggered by NodeEgress onSaved -> refresh() (older seq=2), intentionally delayed!
          return new Promise<Response>((resolve) => {
            resolveOldRefresh = resolve;
          });
        }
        // Triggered later by pools poll() (newer seq=3), resolves FIRST!
        const newerPoll = fixtureInventory(Date.now());
        newerPoll.relayPools![0].name = "AP Pool Newer Poll";
        return new Response(JSON.stringify(newerPoll), { headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
    }),
  );

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  try {
    await act(async () => {
      root.render(<GlivelaControl standalone />);
      await vi.advanceTimersByTimeAsync(0);
    });

    // Expand Direct Exit on nodes page and submit NodeEgress -> triggers onEgressSaved -> refresh() (seq=2)
    const directRowBtn = [...div.querySelectorAll("button.gl-node-name")].find((b) => b.textContent?.includes("Direct Exit")) as HTMLButtonElement;
    await act(async () => {
      directRowBtn.click();
      await vi.advanceTimersByTimeAsync(0);
    });
    const addrInput = div.querySelector('form[aria-label="落地端出口选择"] input') as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    await act(async () => {
      setter?.call(addrInput, "203.0.113.21");
      addrInput.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const saveEgressBtn = div.querySelector('form[aria-label="落地端出口选择"] button[type="submit"]') as HTMLButtonElement;
    await act(async () => {
      saveEgressBtn.click();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(businessCall).toBe(2);

    // Switch to pools page while refresh (seq=2) is still in flight; advance 15s -> poll() (seq=3) resolves FIRST
    const poolsNav = [...div.querySelectorAll("nav button")].find((b) => b.textContent?.includes("中转池与拓扑")) as HTMLButtonElement;
    await act(async () => poolsNav.click());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(businessCall).toBe(3);
    expect(div.textContent).toContain("AP Pool Newer Poll");

    // Delayed older refresh (seq=2) now arrives out-of-order -> MUST NOT overwrite newer poll snapshot
    const staleRefresh = fixtureInventory(baseNow);
    staleRefresh.relayPools![0].name = "AP Pool Stale Refresh";
    resolveOldRefresh?.(new Response(JSON.stringify(staleRefresh), { headers: { "Content-Type": "application/json" } }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(div.textContent).toContain("AP Pool Newer Poll");
    expect(div.textContent).not.toContain("AP Pool Stale Refresh");
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});

it("polls business on visible pools page for late Observatory/revocation updates and prevents stale poll overwrite", async () => {
  vi.useFakeTimers();
  const baseNow = Date.parse("2026-11-28T12:00:00Z");
  vi.setSystemTime(baseNow);
  Object.defineProperty(document, "hidden", { configurable: true, value: false });

  const initialInv = fixtureInventory(baseNow);
  initialInv.observatoryPaths = [];
  initialInv.socketCutovers = [
    {
      id: "cutover-1",
      targetNodeId: "landing-twohop",
      address: "198.51.100.20",
      port: 24000,
      phase: "listener-pending",
      listenerRevision: "4",
      listenerApplied: false,
      pendingEntries: [],
      consumerEntryIds: ["entry-a"],
    },
  ];

  let businessCall = 0;
  let releaseStalePoll: ((res: Response) => void) | undefined;
  let stalePollAborted = false;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/ip-quality")) {
        return new Response(JSON.stringify({ targets: [], checks: [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (url.endsWith("/route-latencies")) {
        return new Response(JSON.stringify({ latencies: [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (url.endsWith("/network-optimization")) {
        return new Response(JSON.stringify({ nodes: [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (url.endsWith("/link-speeds")) {
        return new Response(JSON.stringify({ revision: "0", tests: [], channels: [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (url.endsWith("/relay-pools")) {
        return new Response(JSON.stringify({ poolId: "pool-ap", revision: "4", revocation: { pendingEntries: [], pendingLandings: [], complete: true } }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.endsWith("/business")) {
        businessCall += 1;
        if (businessCall === 1) {
          return new Response(JSON.stringify(initialInv), { headers: { "Content-Type": "application/json" } });
        }
        if (businessCall === 2) {
          // Background poll #1: late Observatory sample arrives + revocation completes + cutover receipt applied
          const updated = fixtureInventory(Date.now());
          updated.relayPools![0].revocation = { pendingEntries: [], pendingLandings: [], complete: true };
          updated.socketCutovers = [{ ...initialInv.socketCutovers![0], listenerApplied: true }];
          return new Response(JSON.stringify(updated), { headers: { "Content-Type": "application/json" } });
        }
        if (businessCall === 3) {
          // Background poll #2 stays in flight while a mutation occurs -> must be aborted and never overwrite rev 4!
          return new Promise<Response>((resolve, reject) => {
            init?.signal?.addEventListener("abort", () => {
              stalePollAborted = true;
              reject(new DOMException("Aborted", "AbortError"));
            });
            releaseStalePoll = resolve;
          });
        }
        // Post-mutation refresh returns rev 4 with renamed pool
        const afterMutation = fixtureInventory(Date.now());
        afterMutation.relayPools![0].revision = "4";
        afterMutation.relayPools![0].name = "AP Pool Rev4";
        return new Response(JSON.stringify(afterMutation), { headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
    }),
  );

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  try {
    await act(async () => {
      root.render(<GlivelaControl standalone />);
      await vi.advanceTimersByTimeAsync(0);
    });

    // Switch to pools page -> background 15s polling starts
    const poolsNav = [...div.querySelectorAll("nav button")].find((b) => b.textContent?.includes("中转池与拓扑")) as HTMLButtonElement;
    await act(async () => poolsNav.click());
    expect(div.textContent).toContain("尚无观测样本");

    // Advance 15s: late Observatory sample, revocation completion, and cutover receipt arrive cleanly without staleness
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(div.textContent).toContain("36ms");
    expect(div.textContent).toContain("节点应用回执已同步");
    const cutoverSubTab = [...div.querySelectorAll("button")].find((b) => b.textContent?.includes("端口 24000 切窗与迁移")) as HTMLButtonElement;
    await act(async () => cutoverSubTab.click());
    expect(div.textContent).toContain("监听回执已确认");
    const poolsSubTab = [...div.querySelectorAll("button")].find((b) => b.textContent?.includes("中转池管理")) as HTMLButtonElement;
    await act(async () => poolsSubTab.click());

    // Advance another 15s: background poll #2 starts and hangs in flight
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(businessCall).toBe(3);

    // Trigger a mutation while poll #2 is in flight -> poll #2 is aborted, post-mutation rev 4 wins
    const moveDownBtn = div.querySelector('button[aria-label="下移 AP Pool 成员 Relay One"]') as HTMLButtonElement;
    await act(async () => {
      moveDownBtn.click();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(stalePollAborted).toBe(true);
    expect(div.textContent).toContain("AP Pool Rev4");
    // Even if stale promise tried to settle, it cannot clobber the newer snapshot
    releaseStalePoll?.(new Response(JSON.stringify(initialInv), { headers: { "Content-Type": "application/json" } }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(div.textContent).toContain("AP Pool Rev4");

    // Hiding the document stops background polling while hidden
    const countBeforeHide = businessCall;
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(businessCall).toBe(countBeforeHide);

    // Navigating away to Nodes stops background business polling even when visible
    Object.defineProperty(document, "hidden", { configurable: true, value: false });
    const nodesNav = [...div.querySelectorAll("nav button")].find((b) => b.textContent?.includes("节点")) as HTMLButtonElement;
    await act(async () => nodesNav.click());
    const countBeforeLeave = businessCall;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(businessCall).toBe(countBeforeLeave);
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});

it("sends allowlisted RouteChange payloads when toggling a pooled route in RouteWorkspace", async () => {
  const now = Date.parse("2026-11-28T12:00:00Z");
  const inv = fixtureInventory(now);
  const names = new Map(inv.nodes.map((n) => [n.id, n.name]));
  const save = vi.fn(async () => true);

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  try {
    await act(async () => {
      root.render(
        <RouteWorkspace
          inventory={inv}
          names={names}
          disabled={false}
          save={save}
          latency={{ values: new Map(), now, busy: false, error: "", refresh: vi.fn(async () => {}) }}
          loadSpeeds={vi.fn(async () => ({ revision: "0", tests: [], channels: [] }))}
          active={false}
        />,
      );
    });

    const pooledBtn = [...div.querySelectorAll("button.gl-route-name")].find((b) => b.textContent === "Fixed Exit") as HTMLButtonElement;
    await act(async () => {
      pooledBtn.click();
    });
    expect(div.querySelector(".gl-inspector")?.textContent).toContain("AP Pool");
    expect(div.querySelector(".gl-inspector")?.textContent).toContain("36 ms");

    const disableBtn = [...div.querySelectorAll(".gl-inspector button")].find((b) => b.textContent === "停用线路") as HTMLButtonElement;
    await act(async () => {
      disableBtn.click();
    });
    expect(save).toHaveBeenCalledWith("routes", {
      id: "route-pooled",
      accountId: "acct-1",
      entryId: "entry-a",
      egressId: "landing-pooled",
      relayPoolId: "pool-ap",
      hideNative: false,
      enabled: false,
      expectedRevision: "9",
    });
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});
