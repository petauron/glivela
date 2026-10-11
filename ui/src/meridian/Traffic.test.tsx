// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "@/api";
import type { AppData } from "@/App";
import { MeridianTrafficPanel } from "./Traffic";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
afterEach(() => { if (root) act(() => root?.unmount()); root=undefined; document.body.replaceChildren(); vi.restoreAllMocks(); });
const data = { applications: [], services: [], publications: [] } as unknown as AppData;
const line = { entryNodeId: "entry-test", entryName: "Entry A", uploadBytes: 1024, downloadBytes: 2048, totalBytes: 3072, credentialCount: 2, trackedCredentials: 2, startedAt: "2026-10-01T00:00:00Z", observedAt: "2026-10-01T01:00:00Z", state: "stale" as const };
async function mount() { const div=document.createElement("div"); document.body.append(div); root=createRoot(div); await act(async()=>{root?.render(<MeridianTrafficPanel data={data} language="zh-CN" />);}); }
it("shows historical direction totals and coverage without probes or quota changes", async()=>{
 const read=vi.spyOn(api,"meridianTraffic").mockResolvedValue({lines:[line,{...line,entryNodeId:"unknown",entryName:"Entry B",state:"missing",trackedCredentials:0}],period:"since_tracking_started",checkedAt:line.observedAt});
 const probe=vi.spyOn(api,"checkMeridianLinkBandwidth");
 await mount();
 expect(document.body.textContent).toContain("历史用量");
 expect(document.body.textContent).toContain("1 KiB");
 expect(document.body.textContent).toContain("2 KiB");
 expect(document.body.textContent).toContain("3 KiB");
 expect(document.body.textContent).toContain("待采集");
 expect(document.body.textContent).toContain("非月度账单");
 expect(document.body.textContent).toContain("Senulun 入口不可用");
 const missing=Array.from(document.querySelectorAll("tr")).find(r=>r.textContent?.includes("Entry B"))!;
 expect(missing.textContent).not.toContain("KiB");
 const refresh=Array.from(document.querySelectorAll("button")).find(b=>b.textContent?.includes("刷新用量"))!;
 await act(async()=>refresh.click());
 expect(read).toHaveBeenCalledTimes(2); expect(probe).not.toHaveBeenCalled();
});
it("renders read errors instead of fabricated zero totals",async()=>{
 vi.spyOn(api,"meridianTraffic").mockRejectedValue(new Error("unavailable"));await mount();
 expect(document.querySelector('[role="alert"]')).not.toBeNull();expect(document.querySelector("table")).toBeNull();
});
