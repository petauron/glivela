import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectControl } from "@/components/SelectControl";
import { useControlRequest } from "./ControlAccess";

type PathSnapshot = {
  address: string; checkedAt: string; configured: number; actual: number;
  interface: string; interfaceMtu: number; fingerprint: string;
  canChange: boolean; canRestore: boolean; reason?: string;
};
type PathView = {
  address: string; revision: string; shared: number; supported: boolean; online: boolean;
  pending: boolean; snapshot?: PathSnapshot; result?: { state: string; message: string };
};

export function PathMTU({ routeId, mode, landingId, landingName, disabled }: {
  routeId: string; mode: string; landingId: string; landingName: string; disabled: boolean;
}) {
  const request = useControlRequest();
  const [view, setView] = useState<PathView>();
  const [choice, setChoice] = useState("auto");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const active = useRef<AbortController | null>(null);
  const alive = useRef(false);
  const inFlight = useRef(false);
  const initialized = useRef(false);
  const syncForm = (next: PathView) => {
    setChoice(next.snapshot?.configured ? "manual" : "auto");
    setValue(next.snapshot?.configured ? String(next.snapshot.configured) : "");
  };
  const run = useCallback(async (action: string, previous?: PathView, mtu?: number) => {
    if (!alive.current || inFlight.current) return;
    const controller = new AbortController(); active.current = controller; inFlight.current = true;
    if (action !== "get") setBusy(true);
    try {
      const next = await request<PathView>("path-mtu", {
        routeId, mode, landingId, action, ...(mtu == null ? {} : { mtu }),
        expectedRevision: previous?.revision ?? "0", expected: previous?.snapshot?.fingerprint ?? "",
      }, controller.signal);
      if (!alive.current || controller.signal.aborted) return;
      setView(next); setError("");
      if (!initialized.current && next.snapshot && !next.pending) { syncForm(next); initialized.current = true; }
      return next;
    } catch (failure) {
      if (!controller.signal.aborted && alive.current) setError(failure instanceof Error ? failure.message : "路径状态读取失败");
    } finally {
      if (active.current === controller) { active.current = null; inFlight.current = false; if (alive.current) setBusy(false); }
    }
  }, [request, routeId, mode, landingId]);
  useEffect(() => {
    alive.current = true; initialized.current = false;
    void (async () => {
      const next = await run("get");
      if (next?.supported && next.online && !next.pending) await run("inspect", next);
    })();
    return () => { alive.current = false; active.current?.abort(); active.current = null; inFlight.current = false; };
  }, [run]);
  useEffect(() => {
    if (!view?.pending) return;
    const timer = window.setInterval(() => { if (!document.hidden) void run("get"); }, 500);
    return () => window.clearInterval(timer);
  }, [view?.pending, run]);
  const snap = view?.snapshot;
  const min = view?.address.includes(":") ? 1280 : 576;
  const max = snap && snap.interfaceMtu > 0 ? snap.interfaceMtu : null;
  const number = Number(value);
  const invalid = choice === "manual" && (!/^\d+$/.test(value) || !Number.isSafeInteger(number) || number < min || max !== null && number > max);
  const waiting = busy || !!view?.pending;
  const unavailable = disabled || waiting || !view?.supported || !view.online;
  const fresh = !!snap && Date.now() - Date.parse(snap.checkedAt) <= 120000;
  const apply = async () => {
    if (!view || invalid || !fresh) return;
    await run(choice === "auto" ? "auto" : "set", view, choice === "manual" ? number : 0);
  };
  const inspect = async () => {
    initialized.current = false;
    const next = await run("get");
    if (next?.supported && next.online && !next.pending) await run("inspect", next);
  };
  const message = waiting ? "正在核对路径…" : view?.result?.state === "failed" ? view.result.message : snap?.reason;
  return <section className="gl-path-mtu" aria-label={`${landingName}路径 MTU`}>
    <div className="gl-path-mtu-heading"><h3>路径 MTU</h3><Button size="sm" variant="ghost" disabled={disabled || waiting} onClick={() => void inspect()}>检测</Button></div>
    <p className="gl-context-copy">当前：{snap ? snap.configured ? `手动 ${snap.configured}` : "自动" : "自动 · 未检测"}{snap?.actual ? ` · 路由 MTU ${snap.actual}` : ""}</p>
    <p className="gl-path-mtu-address">{landingName}{view?.address ? ` · ${view.address}` : ""}</p>
    <div className="gl-path-mtu-controls">
      <div><label htmlFor={`path-mtu-mode-${routeId}-${landingId}`}>模式</label><SelectControl id={`path-mtu-mode-${routeId}-${landingId}`} value={choice} onValueChange={setChoice} disabled={unavailable} options={[{ value: "auto", label: "自动" }, { value: "manual", label: "手动" }]} /></div>
      {choice === "manual" ? <div><label htmlFor={`path-mtu-value-${routeId}-${landingId}`}>MTU</label><Input id={`path-mtu-value-${routeId}-${landingId}`} inputMode="numeric" value={value} onChange={event => setValue(event.target.value)} disabled={unavailable} placeholder={max === null ? "先检测路径" : `${min}～${max}`} aria-invalid={invalid} aria-describedby={`path-mtu-help-${routeId}-${landingId}`} /></div> : null}
      <Button size="sm" disabled={unavailable || !fresh || invalid || (choice === "manual" ? !snap?.canChange : !snap?.canChange && !snap?.canRestore) || choice === "auto" && !snap?.configured && !snap?.canRestore} onClick={() => void apply()}>{choice === "auto" ? "恢复自动" : "应用"}</Button>
    </div>
    {invalid ? <p id={`path-mtu-help-${routeId}-${landingId}`} className="gl-path-mtu-error">{max === null ? `请输入不小于 ${min} 的整数。` : `请输入 ${min}～${max} 的整数。`}</p> : null}
    {view && !view.supported ? <p className="gl-context-copy">等待节点能力上报；旧版节点需升级。</p> : null}
    {view && !view.online ? <p className="gl-context-copy">节点离线或尚未就绪。</p> : null}
    {view && view.shared > 1 ? <p className="gl-context-copy">此入口到同一目标的 {view.shared} 条线路共用该设置。</p> : null}
    {error || message ? <p role={error || view?.result?.state === "failed" ? "alert" : "status"} className={error || view?.result?.state === "failed" ? "gl-path-mtu-error" : "gl-context-copy"}>{error || message}</p> : null}
  </section>;
}
