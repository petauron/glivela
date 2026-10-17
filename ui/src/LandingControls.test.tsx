// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "@/api";
import { emptyAppData } from "@/app-data";

const data = emptyAppData({ version: "test", agentInstallerAvailable: true, agentConnectionMode: "lan", agentConnectUrl: "https://center.example.test" });
const mutate = vi.fn(async (operation: () => Promise<unknown>) => { await operation(); });
import type { LandingView } from "@/landing-types";
import type { AgentView } from "@/types";
import { LandingProvider } from "@/views/LandingControls";
import { LandingTableRows } from "./glivela/LandingNodes";
import { GlivelaLinkTests } from "./glivela/LinkTests";
import type { InstalledAppInstance } from "@/views/installed-apps-model";
import { selectedLandingLatencies } from "@/views/landingLatency";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
class LatencyEventSource {
  static instances: LatencyEventSource[] = [];
  constructor() { LatencyEventSource.instances.push(this); }
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  close = vi.fn();
}
beforeEach(() => {
  LatencyEventSource.instances = [];
  vi.stubGlobal("EventSource", LatencyEventSource);
});
afterEach(() => {
  if (root) act(() => root?.unmount());
  root = undefined;
  document.body.replaceChildren();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function overview(): LandingView {
  return {
    nodeIds: ["a", "b"],
    landingRegionCodes: { a: "US", b: "TW" },
    revision: 4,
    status: "applying",
    eligibleEntries: 2,
    readyCombinations: 3,
    failedCombinations: 1,
    withheldCombinations: 2,
    servers: [
      { nodeId: "a", name: "落地 A", status: "ready", inUse: true, eligibleEntries: 2, readyCombinations: 2, failedCombinations: 0, withheldCombinations: 0 },
      { nodeId: "b", name: "落地 B", status: "ready", inUse: true, eligibleEntries: 2, readyCombinations: 1, failedCombinations: 1, withheldCombinations: 2 },
    ],
    candidates: [{ nodeId: "c", name: "落地 C" }],
    proxies: [],
    latencies: [
      { nodeId: "source-one", landingNodeId: "a", state: "direct", latencyMs: 12, checkedAt: new Date().toISOString() },
      { nodeId: "source-one", landingNodeId: "b", state: "direct", latencyMs: 128, checkedAt: new Date().toISOString() },
    ],
  };
}

it("shows every global landing latency and never includes self-to-self", () => {
  const view = overview();
  expect(selectedLandingLatencies(view, "source-one", "entry-one")).toHaveLength(2);
  expect(selectedLandingLatencies(view, "a", "entry-on-a").map((pair) => pair.server.nodeId)).toEqual(["b"]);
});

it("sorts measured global landing latency from fastest to slowest", () => {
  const view = overview();
  view.latencies = view.latencies.map((latency) => ({ ...latency, latencyMs: latency.landingNodeId === "a" ? 128 : 12 }));
  view.servers.push({ nodeId: "c", name: "落地 C", status: "ready", inUse: true, eligibleEntries: 2, readyCombinations: 0, failedCombinations: 0, withheldCombinations: 0 });
  view.nodeIds.push("c");
  expect(selectedLandingLatencies(view, "source-one", "entry-one").map((pair) => pair.server.nodeId)).toEqual(["b", "a", "c"]);
});

it("shows per-server routes and settings inline with locations", async () => {
  vi.spyOn(api, "landing").mockResolvedValue(overview());
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<LandingProvider enabled><table><tbody><LandingTableRows language="zh-CN" search="" purpose="all" order="quality" data={data} mutate={mutate} onCompare={vi.fn()} /></tbody></table></LandingProvider>); });
  expect(container.textContent).toContain("美国");
  expect(container.textContent).toContain("台湾");
  expect(container.textContent).not.toContain("管理落地机");
  await act(async () => { container.querySelector<HTMLButtonElement>('[aria-label="落地 B 操作"]')?.click(); });
  await act(async () => { Array.from(document.querySelectorAll<HTMLElement>('[role="menuitem"]')).find((item) => item.textContent === "落地设置")?.click(); });
  expect(document.body.textContent).toContain("加入订阅");
  expect(document.body.textContent).toContain("1 条线路");
  expect(document.body.textContent).not.toContain("配置账号路由");
});

it("removes an in-use server through the global draining operation", async () => {
  const view = overview();
  vi.spyOn(api, "landing").mockResolvedValue(view);
  const update = vi.spyOn(api, "selectLanding").mockResolvedValue({ ...view, nodeIds: ["a"], retiringNodeIds: ["b"], revision: 5 });
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<LandingProvider enabled><table><tbody><LandingTableRows language="zh-CN" search="" purpose="all" order="quality" data={data} mutate={mutate} onCompare={vi.fn()} /></tbody></table></LandingProvider>); });
  await act(async () => { container.querySelector<HTMLButtonElement>('[aria-label="落地 B 操作"]')?.click(); });
  await act(async () => { Array.from(document.querySelectorAll<HTMLElement>('[role="menuitem"]')).find((item) => item.textContent === "落地设置")?.click(); });
  await act(async () => { document.querySelector<HTMLButtonElement>('[aria-label="移除 落地 B"]')?.click(); });
  expect(update).toHaveBeenCalledWith(["a"], 4, { a: "US" }, expect.any(AbortSignal));
});

it("repairs missing landing regions before republishing subscriptions", async () => {
  const view = overview();
  view.landingRegionCodes = { a: "US" };
  vi.spyOn(api, "landing").mockResolvedValue(view);
  vi.spyOn(api, "agentRegionSuggestion").mockResolvedValue({ agentId: "b", publicAddress: "203.0.113.2", regionCode: "TW", prefix: "", source: "configured_helper" });
  const update = vi.spyOn(api, "selectLanding").mockResolvedValue({ ...view, landingRegionCodes: { a: "US", b: "TW" }, revision: 5 });
  const agents = [{ id: "b", publicEgress: { address: "203.0.113.2" } }] as AgentView[];
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<LandingProvider enabled agents={agents}><table><tbody><LandingTableRows language="zh-CN" search="" purpose="all" order="quality" data={data} mutate={mutate} onCompare={vi.fn()} /></tbody></table></LandingProvider>); });
  await act(async () => {});
  const repair = Array.from(document.querySelectorAll("button")).find((button) => button.textContent?.includes("同步地区并修复订阅"));
  expect(repair).toBeTruthy();
  await act(async () => { repair?.click(); });
  expect(update).toHaveBeenCalledWith(["a", "b"], 4, { a: "US", b: "TW" }, expect.any(AbortSignal));
});

it("shows the selected landing's latency without mixing other landings", async () => {
  vi.spyOn(api, "landing").mockResolvedValue(overview());
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<LandingProvider enabled><GlivelaLinkTests instances={[{ application: { id: "entry-one", nodeId: "source-one" }, realityServices: [] } as unknown as InstalledAppInstance]} language="zh-CN" entryId="" landingId="a" onEntryChange={vi.fn()} onLandingChange={vi.fn()} /></LandingProvider>); });
  expect(container.textContent).toContain("12 ms");
  expect(container.textContent).not.toContain("128 ms");
});

it("keeps the independently built link view live after its event stream stalls", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-18T00:00:00Z"));
  const request = vi.spyOn(api, "landing").mockResolvedValue(overview());
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<LandingProvider enabled><GlivelaLinkTests instances={[{ application: { id: "entry-one", nodeId: "source-one" }, realityServices: [] } as unknown as InstalledAppInstance]} language="zh-CN" entryId="" landingId="a" onEntryChange={vi.fn()} onLandingChange={vi.fn()} /></LandingProvider>); });
  await act(async () => { LatencyEventSource.instances[0].onmessage?.(new MessageEvent("message", { data: JSON.stringify({ revision: 4, reset: true, upserts: overview().latencies, removed: [] }) })); });
  request.mockImplementation(async () => {
    const next = overview();
    next.latencies[0].latencyMs = 24;
    return next;
  });
  await act(async () => { await vi.advanceTimersByTimeAsync(195_000); });
  expect(container.textContent).toContain("24 ms");
  expect(container.textContent).not.toContain("12 ms");
});

it("retains display evidence across a 60 second sample gap but expires it after three minutes", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-18T00:00:00Z"));
  const request = vi.spyOn(api, "landing").mockResolvedValue(overview());
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<LandingProvider enabled><GlivelaLinkTests instances={[{ application: { id: "entry-one", nodeId: "source-one" }, realityServices: [] } as unknown as InstalledAppInstance]} language="zh-CN" entryId="" landingId="a" onEntryChange={vi.fn()} onLandingChange={vi.fn()} /></LandingProvider>); });
  request.mockRejectedValue(new Error("offline"));
  await act(async () => { await vi.advanceTimersByTimeAsync(61_000); });
  expect(container.textContent).toContain("12 ms");
  await act(async () => { await vi.advanceTimersByTimeAsync(120_000); });
  expect(container.textContent).not.toContain("12 ms");
});
