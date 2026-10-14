// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "@/api";
import { SourceRecovery } from "./SourceRecovery";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
afterEach(() => {
  if (root) act(() => root?.unmount());
  root = undefined;
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

const evidence = { previousFingerprint: "a".repeat(64), currentFingerprint: "b".repeat(64), previousAddress: "100.64.0.61", currentAddress: "100.64.0.61", endpointRevision: 7, observedAt: "2026-09-01T00:00:00Z" };
const onRun = async (_key: string, operation: () => Promise<unknown>) => { try { await operation(); } catch { /* Parent renders the error. */ } };
function button(text: string) {
  const element = Array.from(document.querySelectorAll("button")).find((value) => value.textContent === text);
  if (!element) throw new Error(`Missing button: ${text}`);
  return element;
}
async function mount() {
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<SourceRecovery endpointId="example-entry" language="zh-CN" busy="" onRun={onRun} />); });
  document.querySelector("details")!.open = true;
}

it("requires inspection and confirmation before sending the exact reviewed evidence", async () => {
  const inspect = vi.spyOn(api, "meridianSourceRecovery").mockResolvedValue(evidence);
  const recover = vi.spyOn(api, "recoverMeridianSource").mockResolvedValue({ queued: true });
  await mount();
  expect(inspect).not.toHaveBeenCalled();
  await act(async () => button("检查重装身份").click());
  expect(inspect).toHaveBeenCalledWith("example-entry");
  expect(button("确认身份并恢复线路").disabled).toBe(true);
  expect(recover).not.toHaveBeenCalled();
  await act(async () => document.querySelector<HTMLButtonElement>('[role="switch"]')!.click());
  await act(async () => button("确认身份并恢复线路").click());
  expect(recover).toHaveBeenCalledExactlyOnceWith("example-entry", evidence);
  expect(document.querySelector('[role="status"]')?.textContent).toContain("恢复已提交");
});

it("discards the review after a rejected replacement and requires a new inspection", async () => {
  const inspect = vi.spyOn(api, "meridianSourceRecovery").mockResolvedValue(evidence);
  vi.spyOn(api, "recoverMeridianSource").mockRejectedValue(new Error("identity changed"));
  await mount();
  await act(async () => button("检查重装身份").click());
  await act(async () => document.querySelector<HTMLButtonElement>('[role="switch"]')!.click());
  await act(async () => button("确认身份并恢复线路").click());
  expect(document.querySelector('[role="switch"]')).toBeNull();
  expect(document.querySelector('[role="status"]')).toBeNull();
  await act(async () => button("检查重装身份").click());
  expect(inspect).toHaveBeenCalledTimes(2);
  expect(button("确认身份并恢复线路").disabled).toBe(true);
});

it("a configuration revision change unmounts the previous confirmation", async () => {
  vi.spyOn(api, "meridianSourceRecovery").mockResolvedValue(evidence);
  await mount();
  await act(async () => button("检查重装身份").click());
  await act(async () => document.querySelector<HTMLButtonElement>('[role="switch"]')!.click());
  await act(async () => { root?.render(<SourceRecovery key="example-entry:8" endpointId="example-entry" language="zh-CN" busy="" onRun={onRun} />); });
  expect(document.querySelector('[role="switch"]')).toBeNull();
  expect(button("检查重装身份")).toBeTruthy();
});
