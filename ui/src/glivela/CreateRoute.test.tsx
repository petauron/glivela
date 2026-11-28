// @vitest-environment jsdom
import { act, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import type { Inventory } from "./control-types";
import { CreateRoute } from "./ControlForms";

vi.mock("@/components/SelectControl", () => ({
  SelectControl: ({
    id,
    value,
    onValueChange,
    options,
    disabled,
    placeholder,
    "aria-label": ariaLabel,
  }: {
    id?: string;
    value: string;
    onValueChange: (value: string) => void;
    options: readonly { value: string; label: ReactNode; disabled?: boolean }[];
    disabled?: boolean;
    placeholder?: ReactNode;
    "aria-label"?: string;
  }) => (
    <select id={id} aria-label={ariaLabel} disabled={disabled} value={value} onChange={(e) => onValueChange(e.target.value)}>
      {placeholder ? <option value="">{placeholder}</option> : null}
      {options.map((opt) => (
        <option key={opt.value} value={opt.value} disabled={opt.disabled}>
          {opt.label}
        </option>
      ))}
    </select>
  ),
}));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => {
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

const inventory: Inventory = {
  state: "owned",
  accounts: [
    {
      account: { id: "acct-1", displayName: "Primary", desiredRevision: "9", plan: { totalBytes: "0", expiryTime: "0", resetDays: 0, enabled: true } },
      usage: [],
      schedule: { nextResetAt: "" },
      traffic: {},
    },
  ],
  endpoints: [],
  nodes: [
    { id: "entry-capable", name: "Entry Capable" },
    { id: "entry-old", name: "Entry Old" },
    { id: "landing-dual", name: "Dual-Stack Exit" },
  ],
  runtimes: [
    { id: "entry-capable", role: "entry", revision: "5", appliedRevision: "5", runtimeReady: true, relayPoolCapable: true, publicIpv4: "198.51.100.2", reportedAt: "", peers: [] },
    { id: "entry-old", role: "entry", revision: "2", appliedRevision: "2", runtimeReady: true, relayPoolCapable: false, publicIpv4: "198.51.100.3", reportedAt: "", peers: [] },
    {
      id: "landing-dual",
      certificateId: "d".repeat(64),
      role: "landing",
      revision: "6",
      appliedRevision: "6",
      runtimeReady: true,
      relayPoolCapable: true,
      publicIpv4: "198.51.100.30",
      publicIpv6: "2001:db8::30",
      egressIp: "203.0.113.30",
      reportedAt: "",
      peers: [],
    },
  ],
  relayPools: [
    {
      id: "pool-v4",
      name: "IPv4 Pool",
      revision: "2",
      strategy: { expected: 1, maxRttMs: 500 },
      members: [{ nodeId: "relay-1", certificateId: "a".repeat(64), ingressIpv4: "198.51.100.11", egressIpv4: "198.51.100.11", drained: false, nodeSuspended: false, runtimeReady: true }],
      routeIds: [],
    },
  ],
  routes: [],
};

it("keeps landingAddress empty for dual-stack backend default, allows explicit address selection, and blocks incapable entries", async () => {
  const names = new Map(inventory.nodes.map((n) => [n.id, n.name]));
  const save = vi.fn(async () => true);

  const div = document.createElement("div");
  document.body.append(div);
  const root = createRoot(div);
  try {
    await act(async () => {
      root.render(
        <CreateRoute
          inventory={inventory}
          names={names}
          disabled={false}
          save={save}
          latencies={new Map()}
          now={Date.now()}
          latencyFailed={false}
        />,
      );
    });

    const pooledModeBtn = [...div.querySelectorAll("button")].find((b) => b.textContent === "三跳中转池") as HTMLButtonElement;
    await act(async () => pooledModeBtn.click());

    const selectSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set;
    const pick = async (label: string, val: string) => {
      const sel = div.querySelector(`select[aria-label="${label}"]`) as HTMLSelectElement;
      expect(sel).not.toBeNull();
      await act(async () => {
        selectSetter?.call(sel, val);
        sel.dispatchEvent(new Event("change", { bubbles: true }));
      });
    };

    await pick("账户", "acct-1");
    await pick("入口", "entry-old");
    await pick("中转池", "pool-v4");
    await pick("固定出口落地", "landing-dual");

    // Incapable entry keeps submit disabled and explains why
    const submitBtn = () => div.querySelector('button[type="submit"]') as HTMLButtonElement;
    expect(submitBtn().disabled).toBe(true);
    expect(div.textContent).toContain("尚未上报中转池渲染能力");

    // Capable entry + dual-stack landing leaves landingAddress empty -> omits landingAddress so backend chooses default
    await pick("入口", "entry-capable");
    await pick("固定出口落地", "landing-dual");
    expect(submitBtn().disabled).toBe(false);

    await act(async () => submitBtn().click());
    const [op1, payload1] = save.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(op1).toBe("routes");
    expect(payload1.relayPoolId).toBe("pool-v4");
    expect(payload1.egressId).toBe("landing-dual");
    expect("landingAddress" in payload1).toBe(false);
    expect("expectedExit" in payload1).toBe(false);

    // Explicitly clicking the IPv4 hint button fills and submits landingAddress
    const ipv4HintBtn = [...div.querySelectorAll("button")].find((b) => b.textContent?.includes("指定 IPv4：198.51.100.30")) as HTMLButtonElement;
    expect(ipv4HintBtn).toBeDefined();
    await act(async () => ipv4HintBtn.click());
    await act(async () => submitBtn().click());
    const [, payload2] = save.mock.calls[1] as unknown as [string, Record<string, unknown>];
    expect(payload2.landingAddress).toBe("198.51.100.30");
  } finally {
    await act(async () => root.unmount());
    div.remove();
  }
});
