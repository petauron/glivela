// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { api, APIError } from "./api";

afterEach(() => { vi.unstubAllGlobals(); document.cookie = "vastora_csrf=; Max-Age=0; path=/"; });
it("keeps the host session, CSRF and cancellation contract for landing updates", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ revision: 2 })));
  vi.stubGlobal("fetch", fetch);
  document.cookie = "vastora_csrf=test-csrf; path=/";
  const controller = new AbortController();
  await api.selectLanding(["exit"], 1, { exit: "TW" }, controller.signal);
  const [url, options] = fetch.mock.calls[0];
  expect(url).toBe("/api/v1/meridian/landing");
  expect(options.credentials).toBe("same-origin");
  expect(options.signal).toBe(controller.signal);
  expect(options.headers.get("X-CSRF-Token")).toBe("test-csrf");
  expect(JSON.parse(options.body)).toEqual({ nodeIds: ["exit"], revision: 1, landingRegionCodes: { exit: "TW" } });
});
it("preserves authorization failures without retrying writes", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: "Forbidden", code: "forbidden" }), { status: 403 }));
  vi.stubGlobal("fetch", fetch);
  await expect(api.selectLanding([], 1, {})).rejects.toMatchObject({ status: 403, code: "forbidden", name: new APIError("", 403).name });
  expect(fetch).toHaveBeenCalledTimes(1);
});
