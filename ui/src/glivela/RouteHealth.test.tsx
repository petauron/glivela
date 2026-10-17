// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { RouteHealth } from "./RouteHealth";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
afterEach(() => { if (root) act(() => root?.unmount()); root = undefined; document.body.replaceChildren(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const checkedAt = "2026-10-01T01:00:00Z";
const leg = { role: "primary", state: "blocked", linkState: "direct", stage: "tls_handshake", reason: "timeout", durationMs: 5000, checkedAt, lastHealthyAt: checkedAt };
async function mount() {
  const container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  await act(async () => root?.render(<RouteHealth routeId="route-example" language="zh-CN" primaryName="Exit A" ipv4Name="Exit B" />));
}
async function open() {
  await act(async () => { const details = document.querySelector("details")!; details.open = true; details.dispatchEvent(new Event("toggle", { bubbles: true })); });
}
it("loads only expanded routes, distinguishes expiry from TLS, and displays both exits", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ checkedAt, current: { status: "blocked", reason: "evidence_expired", receivedAt: checkedAt, legs: [leg, { ...leg, role: "ipv4", stage: "http_response", reason: "unexpected_http_status", httpStatus: 403 }] }, history: [{ status: "blocked", reason: "transport_unverified", observedAt: checkedAt, legs: [leg] }] }) });
  vi.stubGlobal("fetch", fetch); await mount(); expect(fetch).not.toHaveBeenCalled();
  await open();
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/meridian/routes/route-example/health");
  expect(document.body.textContent).toContain("验证结果过期");
  expect(document.body.textContent).toContain("TLS 握手");
  expect(document.body.textContent).toContain("HTTP 403");
  expect(document.body.textContent).toContain("Exit B");
  expect(document.body.textContent).toContain("Center 收到上报");
  const refresh = Array.from(document.querySelectorAll("button")).find((b) => b.textContent?.includes("刷新诊断"))!;
  await act(async () => refresh.click()); expect(fetch).toHaveBeenCalledTimes(2);
});
it("shows read errors without claiming a healthy route", async () => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("unavailable")));
  await mount(); await open(); expect(document.querySelector('[role="alert"]')).not.toBeNull();
  expect(document.body.textContent).not.toContain("验证通过");
});
