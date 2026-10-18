// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "@/api";
import type { AppData } from "@/host-contract";
import type { LandingView } from "@/landing-types";
import { GlivelaRoutes } from "./Routes";

vi.mock("@/components/SelectControl", () => ({
  SelectControl: ({ id, value, onValueChange, disabled, options, "aria-label": label }: {
    id?: string; value: string; onValueChange: (value: string) => void; disabled?: boolean;
    options: { value: string; label: string; disabled?: boolean }[]; "aria-label"?: string;
  }) => <select id={id} aria-label={label} value={value} disabled={disabled} onChange={(event) => onValueChange(event.target.value)}>{options.map((option) => <option key={option.value} value={option.value} disabled={option.disabled}>{option.label}</option>)}</select>,
}));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | undefined;
afterEach(() => { if (root) act(() => root?.unmount()); root = undefined; document.body.replaceChildren(); vi.restoreAllMocks(); });
const data = {
  agents: [], meridian: { accounts: [{ id: "account", enabled: true, displayName: "Account" }],
    endpoints: [{ id: "endpoint", nodeId: "entry", vless: true, status: "ready" }], grants: [],
    cutover: { subscriptionAuthority: "meridian", state: "complete" } },
} as unknown as AppData;
const servers = [
  { nodeId: "exit6", name: "IPv6 A", status: "ready", egressIp: "2606:4700:4700::1111" },
  { nodeId: "exit4", name: "IPv4 B", status: "ready", egressIp: "1.1.1.1" },
  { nodeId: "entry", name: "Entry", status: "ready", egressIp: "1.0.0.1" },
  { nodeId: "offline", name: "Offline", status: "failed", egressIp: "8.8.8.8" },
] as LandingView["servers"];
async function mount(landings = servers) {
  const container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  await act(async () => { root?.render(<GlivelaRoutes data={data} language="zh-CN" endpointId="endpoint" landingServers={landings} mutate={async (operation) => { await operation(); }} />); });
}
async function select(element: HTMLSelectElement, value: string) {
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(element, value); element.dispatchEvent(new Event("change", { bubbles: true })); });
}
it("sends one composite identity with two independent, ready exits", async () => {
  const create = vi.spyOn(api, "createMeridianRoute").mockResolvedValue({ id: "combo" } as Awaited<ReturnType<typeof api.createMeridianRoute>>);
  await mount();
  await select(document.querySelector("select")!, "composite");
  const primary = document.querySelector<HTMLSelectElement>('select[aria-label="IPv6 主落地"]')!;
  expect(Array.from(primary.options).map((option) => option.value)).toEqual(["", "exit6"]);
  await select(primary, "exit6");
  const secondary = Array.from(document.querySelectorAll("select")).find((element) => element.id.endsWith("-ipv4"))!;
  expect(Array.from(secondary.options).map((option) => option.value)).toEqual(["", "exit4"]);
  await select(secondary, "exit4");
  const submit = document.querySelector<HTMLButtonElement>('button[type="submit"]')!;
  expect(submit.disabled).toBe(false);
  await act(async () => submit.click());
  expect(create).toHaveBeenCalledExactlyOnceWith({ accountId: "account", endpointId: "endpoint", egressNodeId: "exit6", ipv4EgressNodeId: "exit4", hideNative: false });
  expect(document.body.textContent).toContain("使用官方 Xray");
  expect(document.body.textContent).toContain("按 DNS 返回结果优先走 IPv6");
  expect(document.body.textContent).toContain("连接失败不切换落地");
  expect(document.body.textContent).not.toContain("确认无 AAAA");
});
it("cannot submit a combination without an independent IPv4 exit", async () => {
  const create = vi.spyOn(api, "createMeridianRoute");
  await mount(servers.filter((server) => server.nodeId !== "exit4"));
  await select(document.querySelector("select")!, "composite");
  await select(document.querySelector<HTMLSelectElement>('select[aria-label="IPv6 主落地"]')!, "exit6");
  expect(document.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(true);
  expect(document.body.textContent).toContain("需要另一台已就绪的 IPv4 落地");
  expect(create).not.toHaveBeenCalled();
});
it("keeps the original single-exit submission unchanged", async () => {
  const create = vi.spyOn(api, "createMeridianRoute").mockResolvedValue({ id: "fixed" } as Awaited<ReturnType<typeof api.createMeridianRoute>>);
  await mount();
  await select(document.querySelector<HTMLSelectElement>('select[aria-label="落地机"]')!, "exit4");
  await act(async () => document.querySelector<HTMLButtonElement>('button[type="submit"]')!.click());
  expect(create).toHaveBeenCalledExactlyOnceWith({ accountId: "account", endpointId: "endpoint", egressNodeId: "exit4", ipv4EgressNodeId: undefined, hideNative: false });
});
