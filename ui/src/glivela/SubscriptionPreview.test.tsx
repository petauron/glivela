// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { SubscriptionPreview } from "./SubscriptionPreview";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
afterEach(() => { if (root) act(() => root?.unmount()); root = undefined; document.body.replaceChildren(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function mount(onInspectEndpoint = vi.fn()) {
  const container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  await act(async () => root?.render(<SubscriptionPreview accountId="account-example" language="zh-CN" onInspectEndpoint={onInspectEndpoint} />));
}
async function open() {
  await act(async () => { const details = document.querySelector("details")!; details.open = true; details.dispatchEvent(new Event("toggle", { bubbles: true })); });
}
it("reads on demand, displays actual inventory/source and navigates to existing entry configuration", async () => {
  const inspect = vi.fn();
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ accountId: "account-example", source: "applied_snapshot", appliedRevision: 3, checkedAt: "2026-10-01T01:00:00Z", fingerprint: "digest", count: 1, items: [{ name: "台湾｜双跳·Entry", protocol: "vless-reality" }], excluded: [{ endpointId: "entry-two", name: "Entry two", reason: "publication_pending" }] }) });
  vi.stubGlobal("fetch", fetch); await mount(inspect); expect(fetch).not.toHaveBeenCalled(); await open();
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/meridian/accounts/account-example/subscription-preview");
  expect(fetch.mock.calls[0][1].cache).toBe("no-store");
  expect(document.body.textContent).toContain("实际可订阅 1 条");
  expect(document.body.textContent).toContain("已应用快照");
  expect(document.body.textContent).toContain("台湾｜双跳·Entry");
  expect(document.body.textContent).toContain("公网入口未就绪");
  const button = Array.from(document.querySelectorAll("button")).find((item) => item.textContent === "查看入口配置")!;
  await act(async () => button.click()); expect(inspect).toHaveBeenCalledWith("entry-two");
});
it("shows a successful empty preview and supports retry after a read error", async () => {
  const fetch = vi.fn().mockRejectedValueOnce(new Error("offline")).mockResolvedValue({ ok: true, json: async () => ({ source: "unavailable", checkedAt: "2026-10-01T01:00:00Z", appliedRevision: 1, count: 0, items: [], excluded: [], reason: "account_disabled" }) });
  vi.stubGlobal("fetch", fetch); await mount(); await open(); expect(document.querySelector('[role="alert"]')?.textContent).toContain("暂时无法读取订阅预览");
  const refresh = Array.from(document.querySelectorAll("button")).find((item) => item.textContent === "刷新预览")!;
  await act(async () => refresh.click());
  expect(document.body.textContent).toContain("实际可订阅 0 条"); expect(document.body.textContent).toContain("账号已停用");
});
it("aborts a closed preview and ignores late responses", async () => {
  let finish: (value: unknown) => void = () => {};
  const fetch = vi.fn().mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  vi.stubGlobal("fetch", fetch); await mount(); await open();
  const signal = fetch.mock.calls[0][1].signal as AbortSignal;
  await act(async () => { const details = document.querySelector("details")!; details.open = false; details.dispatchEvent(new Event("toggle", { bubbles: true })); });
  expect(signal.aborted).toBe(true);
  await act(async () => finish({ ok: true, json: async () => ({ count: 99, items: [], excluded: [] }) }));
  expect(document.body.textContent).not.toContain("99");
});

it("explains an expired session without blaming account input", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));
  await mount(); await open();
  expect(document.querySelector('[role="alert"]')?.textContent).toContain("重新登录");
  expect(document.body.textContent).not.toContain("检查填写内容");
});
