// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { api, APIError } from "@/api";
import { emptyAppData } from "@/app-data";
import type { Mutate } from "@/host-contract";
import type { MeridianAccount } from "@/meridian-types";
import type { Application } from "@/types";
import { GlivelaManagerSheet } from "./Manager";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
afterEach(async () => {
  if (root) await act(async () => root?.unmount());
  root = undefined;
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

function account(id: string): MeridianAccount {
  return { id, displayName: id, totalBytes: 1024 ** 3, usedBytes: 100, remainingBytes: 1024 ** 3 - 100, expiryTime: 0, resetDays: 0, enabled: true, desiredRevision: 1, appliedRevision: 1, status: "active", credentialCount: 1, routeCount: 0, updatedAt: "2026-10-01T00:00:00Z" };
}
async function mount(mutate: Mutate = async (operation) => { await operation(); }) {
  vi.spyOn(api, "regions").mockResolvedValue({ regions: [] });
  const data = emptyAppData({ version: "test", agentInstallerAvailable: true, agentConnectionMode: "lan", agentConnectUrl: "https://center.example.test" });
  data.meridian.accounts = [account("account-a"), account("account-b")];
  const element = document.createElement("div"); document.body.append(element); root = createRoot(element);
  await act(async () => root?.render(<GlivelaManagerSheet application={{ id: "controller" } as Application} data={data} language="zh-CN" mutate={mutate} onClose={vi.fn()} />));
}
function button(name: string, scope: ParentNode = document) {
  const result = Array.from(scope.querySelectorAll<HTMLButtonElement>("button")).find((item) => item.textContent?.trim() === name);
  if (!result) throw new Error(`Missing button: ${name}`);
  return result;
}
function form(id = "account-a") {
  return document.querySelector<HTMLFormElement>(`form[aria-label="编辑 ${id} 的套餐"]`);
}
async function edit(index = 0) {
  const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("button")).filter((item) => item.textContent?.trim() === "编辑套餐");
  await act(async () => buttons[index]!.click());
}
async function fill(id = "account-a") {
  await act(async () => {
    const values = { name: "Changed plan", quota: "2.5", reset: "7", expiry: "2027-06-15T08:30" };
    for (const [key, value] of Object.entries(values)) {
      const input = document.getElementById(`meridian-account-${key}-${id}`) as HTMLInputElement;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
}
function assertDraft(id = "account-a") {
  const values = { name: "Changed plan", quota: "2.5", reset: "7", expiry: "2027-06-15T08:30" };
  for (const [key, value] of Object.entries(values)) expect((document.getElementById(`meridian-account-${key}-${id}`) as HTMLInputElement).value).toBe(value);
}

it.each([
  ["network", new TypeError("Failed to fetch")],
  ["conflict", new APIError("conflict", 409)],
  ["server", new APIError("failure", 500)],
])("keeps the complete draft on %s failure and closes only after explicit successful retry", async (_name, failure) => {
  const update = vi.spyOn(api, "updateMeridianAccount").mockRejectedValueOnce(failure).mockResolvedValue(account("account-a"));
  const mutate = vi.fn<Mutate>(async (operation) => { await operation(); });
  await mount(mutate); await edit(); await fill();
  await act(async () => button("保存套餐", form()!).click());
  expect(form()).not.toBeNull(); assertDraft();
  const error = form()!.querySelector('[role="alert"]')!;
  expect(error.textContent).toContain("输入已保留");
  expect(form()!.getAttribute("aria-describedby")).toBe(error.id);
  expect(document.querySelectorAll('[role="alert"]')).toHaveLength(1);
  expect(update).toHaveBeenCalledTimes(1);
  expect(update).toHaveBeenLastCalledWith("account-a", { displayName: "Changed plan", totalBytes: 2.5 * 1024 ** 3, resetDays: 7, expiryTime: new Date("2027-06-15T08:30").getTime(), enabled: true });
  expect(mutate.mock.calls[0][2]).toEqual({ reportError: false });
  await act(async () => button("保存套餐", form()!).click());
  expect(update).toHaveBeenCalledTimes(2);
  expect(form()).toBeNull();
  expect(document.querySelector('[role="alert"]')).toBeNull();
});

it("keeps a failed account error and draft separate from a different account's successful edit", async () => {
  vi.spyOn(api, "updateMeridianAccount").mockImplementation(async (id) => { if (id === "account-a") throw new APIError("conflict", 409); return account(id); });
  await mount(); await edit(); await fill();
  await act(async () => button("保存套餐", form()!).click());
  await edit(); // Only account B still has an Edit plan button.
  expect(form("account-b")!.querySelector('[role="alert"]')).toBeNull();
  await act(async () => button("保存套餐", form("account-b")!).click());
  expect(form("account-b")).toBeNull();
  expect(form()!.querySelector('[role="alert"]')?.textContent).toContain("配置有冲突");
  assertDraft();
});

it("prevents duplicate submissions and edits while the request is pending", async () => {
  let reject: (error: Error) => void = () => {};
  const update = vi.spyOn(api, "updateMeridianAccount").mockImplementation(() => new Promise((_resolve, rejectRequest) => { reject = rejectRequest; }));
  await mount(); await edit(); await fill();
  const current = form()!;
  await act(async () => {
    current.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    current.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  expect(update).toHaveBeenCalledTimes(1);
  expect(current.querySelector("fieldset")!.disabled).toBe(true);
  expect(button("保存套餐", current).disabled).toBe(true);
  await act(async () => reject(new TypeError("Failed to fetch")));
  expect(form()).not.toBeNull(); assertDraft();
  expect(form()!.querySelector("fieldset")!.disabled).toBe(false);
});

it("does not acknowledge a save when the host consumed an authentication failure", async () => {
  vi.spyOn(api, "updateMeridianAccount").mockRejectedValue(new APIError("expired", 401));
  await mount(async (operation) => { try { await operation(); } catch { /* Host opens login. */ } });
  await edit(); await fill();
  await act(async () => button("保存套餐", form()!).click());
  expect(form()).not.toBeNull(); assertDraft();
  expect(form()!.querySelector('[role="alert"]')).not.toBeNull();
});
