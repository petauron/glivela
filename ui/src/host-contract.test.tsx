// @vitest-environment jsdom
import { act } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { mount, apiVersion } from "./index";
import { api } from "./api";
import { emptyAppData } from "./app-data";
import type { AppWorkspaceProps } from "./app-workspaces/types";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); document.body.replaceChildren(); });
it("mounts the managed panel, accepts host updates and opens no host business stream", async () => {
  const close = vi.fn();
  const request = vi.fn(async (url: string) => new Response(JSON.stringify(url.endsWith("/ip-quality") ? { targets: [], checks: [] } : url.endsWith("/link-speeds") ? { tests: [] } : url.endsWith("/network-optimization") ? { nodes: [] } : { state: "pending", accounts: [], endpoints: [{ id: "endpoint-example", entryId: "entry-example", nodeId: "host-example", name: "Glivela", retired: false }], routes: [{ id: "route-example", accountId: "account-example", entryId: "entry-example", egressId: "landing-example", enabled: true, hideNative: false, state: "verified" }], runtimes: [{ id: "entry-example", role: "entry", revision: "1", runtimeReady: true, reportedAt: "2026-01-01T00:00:00Z", peers: ["landing-example"], publicSSHConfigured: false }, { id: "landing-example", role: "landing", revision: "1", runtimeReady: true, reportedAt: "2026-01-01T00:00:00Z", peers: [], publicSSHConfigured: false }], nodes: [{ id: "host-example", name: "Entry Example" }, { id: "landing-example", name: "Landing Example" }] }), { headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", request);
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
    expect(element.textContent).toContain("Glivela 控制端尚未就绪");
    const application = { id: "controller-example", name: "Glivela", nodeId: "node-example", siteId: "site-example", appKey: "vastora-official/meridian", image: "example-image", status: "running", runtime: "docker", updateAvailable: false, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };
    const service = { id: "service-example", applicationId: application.id, siteId: application.siteId, name: "controller", protocol: "https" as const, containerPort: 7443, hostPort: 7443, endpoint: "192.0.2.20:7443", source: "catalog" as const, management: true, status: "ready", createdAt: application.createdAt, updatedAt: application.updatedAt };
    await act(async () => handle!.update({ ...props, language: "en", data: { ...data, services: [service] }, group: { ...props.group, controller: { application, siteName: "example", services: [service], publications: [], realityServices: [], realityPublications: [], locked: false } } }));
    expect(element.querySelector("h1")?.textContent).toBe("节点");
    expect(element.querySelector(".glivela-comparison-table")?.textContent).toContain("Entry Example");
    expect(element.querySelector(".glivela-comparison-table")?.textContent).not.toContain("Glivela");
    expect(element.querySelector(".gl-routes")?.textContent).toContain("入口 · Entry Example");
    expect(element.querySelector(".gl-routes")?.textContent).toContain("Landing Example");
    await act(async () => { (element.querySelector(".gl-route-name") as HTMLButtonElement).click(); });
    expect(element.querySelector('[aria-label="Landing Example线路测速"]')?.textContent).toContain("Landing Example");
    expect(element.querySelector(".gl-routes")?.textContent).not.toContain("Glivela");
    expect(element.querySelector("a")).toBeNull();
    expect(request).toHaveBeenCalledWith("/api/v1/applications/controller-example/panel/v1/admin/business", expect.objectContaining({ method: "POST", credentials: "same-origin" }));

  } finally { if (handle) await act(async () => handle!.unmount()); }
  expect(element.childElementCount).toBe(0);
  expect(close).not.toHaveBeenCalled();
  expect(api.landing).not.toHaveBeenCalled();
  expect(api.ipQuality).not.toHaveBeenCalled();
  expect(api.nodeDiagnostics).not.toHaveBeenCalled();
});
