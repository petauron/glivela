import { describe, expect, it } from "vitest";
import type { IPQualityCheck } from "@/ip-quality-types";
import type { InstalledAppInstance } from "@/views/installed-apps-model";
import { compareSelection, entryAvailable, entryState, matchesEntryPurpose, matchesPurpose } from "./selection";

function report(score: number, overrides: Partial<IPQualityCheck> = {}): IPQualityCheck {
  return { state: "succeeded", checkedAt: new Date().toISOString(), stale: false,
    report: { address: "192.0.2.1", version: "test", scores: [], services: [
      { name: "ChatGPT", status: "Yes" }, { name: "Netflix", status: "Yes" }, { name: "DisneyPlus", status: "Yes" },
    ] },
    assessment: { score, status: "complete", ipType: "hosting" }, ...overrides,
  } as IPQualityCheck;
}
const choice = (name: string, score: number, ready = true, overrides: Partial<IPQualityCheck> = {}) => ({ name, ready, check: report(score, overrides) });

describe("node selection evidence", () => {
  it("keeps an offline high scorer below ready nodes", () => {
    const values = [choice("offline", 99, false), choice("ready", 60)];
    expect(values.sort((a, b) => compareSelection(a, b, "quality")).map((item) => item.name)).toEqual(["ready", "offline"]);
  });
  it("sorts historical and current scores together regardless of report age", () => {
    const values = [choice("old", 99, true, { checkedAt: "2020-01-01T00:00:00Z" }), choice("current", 60)];
    expect(values.sort((a, b) => compareSelection(a, b, "quality"))[0].name).toBe("old");
  });
  it("sorts conservative scores by their displayed value", () => {
    const conservative = report(90);
    conservative.assessment!.status = "conservative";
    const values = [{ name: "incomplete", ready: true, check: conservative }, choice("complete", 60)];
    expect(values.sort((a, b) => compareSelection(a, b, "quality"))[0].name).toBe("incomplete");
  });
  it("uses names to break equal scores, not freshness", () => {
    const values = [choice("Zulu", 70), choice("Alpha", 70, true, { checkedAt: "2020-01-01T00:00:00Z" })];
    expect(values.sort((a, b) => compareSelection(a, b, "quality")).map((item) => item.name)).toEqual(["Alpha", "Zulu"]);
  });
  it("puts unscored, changed-IP, failed and partial reports after scored nodes", () => {
    const changed = report(99); changed.assessment!.status = "ip_changed";
    const partial = report(99); partial.assessment!.status = "partial";
    const values = [
      { name: "changed", ready: true, check: changed },
      { name: "partial", ready: true, check: partial },
      { name: "missing", ready: true },
      choice("failed", 99, true, { state: "failed" }),
      choice("stale", 99, true, { stale: true }),
      choice("scored", 0),
    ];
    expect(values.sort((a, b) => compareSelection(a, b, "quality"))[0].name).toBe("scored");
  });
  it("does not match a changed IP or failed report to a service filter", () => {
    expect(matchesPurpose(report(90, { stale: true }), "ai")).toBe(false);
    expect(matchesPurpose(report(90, { state: "failed" }), "ai")).toBe(false);
    const changed = report(90); changed.assessment!.status = "ip_changed";
    expect(matchesPurpose(changed, "ai")).toBe(false);
  });
  it("requires both full streaming unlocks and excludes app-only ChatGPT", () => {
    const check = report(80);
    expect(matchesPurpose(check, "streaming")).toBe(true);
    check.report!.services[1].status = "Org";
    expect(matchesPurpose(check, "streaming")).toBe(false);
    check.report!.services[0].status = "AppOnly";
    expect(matchesPurpose(check, "ai")).toBe(false);
  });
  it("retains unmeasured nodes in the unfiltered view", () => {
    expect(matchesPurpose(undefined, "all")).toBe(true);
    expect(matchesPurpose(undefined, "ai")).toBe(false);
  });
  it("excludes unavailable entries from use filters while preserving the all-nodes view", () => {
    const instance = { agent: { connected: true, status: "active" }, application: { status: "running" }, realityServices: [{}], realityPublications: [{ status: "failed" }] } as InstalledAppInstance;
    expect(entryState(instance)).toBe("access_error");
    expect(matchesEntryPurpose(instance, report(90), "ai")).toBe(false);
    expect(matchesEntryPurpose(instance, report(90), "all")).toBe(true);
    instance.realityPublications[0].status = "ready";
    expect(matchesEntryPurpose(instance, report(90, { checkedAt: "2020-01-01T00:00:00Z" }), "ai")).toBe(true);
    instance.agent!.connected = false;
    expect(entryState(instance)).toBe("offline");
    expect(matchesEntryPurpose(instance, report(90), "ai")).toBe(false);
  });
  it("does not call a guarded or unsynchronized entry ready", () => {
    const instance = { agent: { connected: true, status: "active" }, application: { status: "running", role: "worker", nodeSyncStatus: "ready" }, controller: {}, realityServices: [{ protocols: ["vless"] }], realityPublications: [{ status: "ready" }] } as InstalledAppInstance;
    expect(entryAvailable(instance)).toBe(true);
    instance.application.nodeSyncStatus = "pending";
    expect(entryAvailable(instance)).toBe(false);
    instance.application.nodeSyncStatus = "ready";
    instance.realityServices[0].guardStatus = "hardening";
    expect(entryAvailable(instance)).toBe(false);
    instance.realityServices[0].guardStatus = "action_required";
    expect(entryAvailable(instance)).toBe(false);
  });
});
