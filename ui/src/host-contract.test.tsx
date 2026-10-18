// @vitest-environment jsdom
import { act } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { mount, apiVersion } from "./index";
import { api } from "./api";
import { emptyAppData } from "./app-data";
import type { AppWorkspaceProps } from "./app-workspaces/types";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); document.body.replaceChildren(); });
it("mounts real pages, accepts host updates and releases its stream on unmount", async () => {
  const close = vi.fn();
  vi.stubGlobal("EventSource", class { close = close; onmessage = null; });
  vi.spyOn(api, "landing").mockResolvedValue({ revision: 1, latencies: [], nodeIds: [], status: "ready", eligibleEntries: 0, readyCombinations: 0, failedCombinations: 0, withheldCombinations: 0, servers: [], candidates: [], proxies: [] });
  vi.spyOn(api, "ipQuality").mockResolvedValue({ checks: [], targets: [] } as unknown as Awaited<ReturnType<typeof api.ipQuality>>);
  vi.spyOn(api, "nodeDiagnostics").mockResolvedValue({ checks: [] });
  const data = emptyAppData({ version: "test", agentInstallerAvailable: true, agentConnectionMode: "lan", agentConnectUrl: "https://center.example.test" });
  const props: AppWorkspaceProps = { data, group: { id: "glivela", appKey: "vastora-official/meridian", instances: [], legacyControllers: [] }, language: "zh-CN", showSite: false, mutate: async operation => { await operation(); }, onManage: vi.fn(), onUpgrade: vi.fn(), onClients: vi.fn(), onReality: vi.fn() };
  const element = document.createElement("div"); document.body.append(element);
  let handle: ReturnType<typeof mount> | undefined;
  try {
    expect(apiVersion).toBe(1);
    await act(async () => { handle = mount(element, props); });
    expect(element.textContent).toContain("线路测速");
    await act(async () => handle!.update({ ...props, language: "en" }));
    expect(element.textContent).toContain("Link tests");
  } finally { if (handle) await act(async () => handle!.unmount()); }
  expect(element.childElementCount).toBe(0);
  expect(close).toHaveBeenCalledTimes(1);
});
