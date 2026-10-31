import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";

type Snapshot = {
  observed: boolean; kernel: string; checkedAt: string; fingerprint: string; scope: string; interface: string; mtu: number; memoryBytes: number;
  congestion: string; available: string[]; defaultQdisc: string; qdisc: string;
  send: number[]; receive: number[]; sendMax: number; receiveMax: number; scaling: number; autoReceive: number;
  canApply: boolean; canRestore: boolean; reason?: string;
};
type Settings = { revision: string; command?: { id: string; action: string; expiresAt: string }; result?: { id: string; state: string; message: string } };
type View = { nodeId: string; state: string; settings: Settings; snapshot?: Snapshot; autoBufferBytes?: number };
type Response = { nodes: View[] };
type Body = { action: string; nodeId?: string; expectedRevision?: string; expected?: string; bufferBytes?: number; confirm?: boolean };
import { useControlRequest } from "./ControlAccess";
export function useNetworkOptimization(enabled: boolean) {
  const request = useControlRequest();
  const [nodes, setNodes] = useState<View[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const inFlight = useRef(false);
  const alive = useRef(false);
  const active = useRef<AbortController | null>(null);
  const run = useCallback(async (body: Body) => {
    if (inFlight.current || !alive.current) return false;
    const controller = new AbortController(); active.current = controller; inFlight.current = true;
    if (body.action !== "list") setBusy(true);
    try {
      const result = await request<Response>("network-optimization", body, controller.signal);
      if (!controller.signal.aborted && alive.current) { setNodes(result.nodes); setError(""); setNow(Date.now()); }
      return !controller.signal.aborted;
    } catch (failure) {
      if (!controller.signal.aborted && alive.current) setError(failure instanceof Error ? failure.message : "状态读取失败。");
      return false;
    } finally {
      if (active.current === controller) { inFlight.current = false; active.current = null; if (alive.current) setBusy(false); }
    }
  }, [request]);
  useEffect(() => {
    alive.current = true;
    if (enabled) void run({ action: "list" });
    const timer = window.setInterval(() => { setNow(Date.now()); if (enabled && !document.hidden) void run({ action: "list" }); }, 5000);
    return () => { alive.current = false; clearInterval(timer); active.current?.abort(); active.current = null; inFlight.current = false; };
  }, [enabled, run]);
  // Only while a user command is pending, refresh promptly; ordinary observation stays at 5 seconds.
  const hasPending = nodes.some(node => !!node.settings.command && !node.settings.result && Date.parse(node.settings.command.expiresAt) > now);
  useEffect(() => {
    if (!enabled || !hasPending) return;
    let cancelled = false; let timer = 0; let attempts = 0;
    const refresh = async () => {
      if (cancelled) return;
      if (!document.hidden) await run({ action: "list" });
      if (!cancelled) { attempts++; timer = window.setTimeout(refresh, attempts < 20 ? 250 : 2000); }
    };
    timer = window.setTimeout(refresh, 250);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [enabled, hasPending, run]);
  return { nodes: new Map(nodes.map(node => [node.nodeId, node])), error, busy, now, run };
}
export type NetworkControl = ReturnType<typeof useNetworkOptimization>;
const pending = (view: View | undefined, now: number) => !!view?.settings.command && !view.settings.result && Date.parse(view.settings.command.expiresAt) > now;
const fresh = (view: View | undefined, now: number) => !!view?.snapshot && view.state === "ready" && now - Date.parse(view.snapshot.checkedAt) < 120000;
function Indicator({ name, enabled, unknown, failed, compact = false }: { name: string; enabled: boolean; unknown: boolean; failed: boolean; compact?: boolean }) {
  const text = unknown ? "未确认" : failed ? "操作失败" : enabled ? "已开启" : "未开启";
  const color = unknown ? "text-muted-foreground" : failed ? "text-destructive" : enabled ? "text-latency-fast" : "text-latency-slow";
  return <span className={`inline-flex items-center gap-1 text-xs ${color}`} title={`${name}：${text}`}><span aria-hidden="true">●</span><span>{compact ? text : `${name} · ${text}`}</span></span>;
}
export function NetworkCell({ nodeId, control, onOpen, summary = false }: { nodeId: string; control: NetworkControl; onOpen: () => void; summary?: boolean }) {
  const view = control.nodes.get(nodeId); const snap = view?.snapshot;
  const unknown = !snap?.observed || !!control.error || !fresh(view, control.now) || pending(view, control.now);
  const failed = view?.settings.result?.state === "failed";
  if (summary) return <button type="button" aria-label="查看网络优化详情" onClick={onOpen}><span className="gl-network-line"><span>BBR</span><Indicator name="BBR" enabled={snap?.congestion === "bbr"} unknown={unknown} failed={failed} compact/></span><span className="gl-network-line"><span>FQ</span><Indicator name="FQ" enabled={snap?.qdisc === "fq"} unknown={unknown} failed={failed} compact/></span></button>;
  return <button type="button" className="flex min-h-11 flex-col justify-center gap-1 rounded px-2 text-left focus-visible:outline focus-visible:outline-2" onClick={onOpen} aria-label="查看网络优化详情"><Indicator name="BBR" enabled={snap?.congestion === "bbr"} unknown={unknown} failed={failed} /><Indicator name="FQ" enabled={snap?.qdisc === "fq"} unknown={unknown} failed={failed} /></button>;
}
const bytes = (n: number | undefined) => n == null || !Number.isFinite(n) ? "—" : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MiB` : `${(n / 1024).toFixed(0)} KiB`;
const triple = (values?: number[]) => values?.some(value => value > 0) ? values.map(bytes).join(" / ") : "—";
export function NetworkPanel({ nodeId, name, control, onClose }: { nodeId: string; name: string; control: NetworkControl; onClose: () => void }) {
  return <Sheet open onOpenChange={open => { if (!open) onClose(); }}>
    <SheetContent className="gl-panel-sheet overflow-y-auto">
      <SheetHeader><SheetTitle>网络优化</SheetTitle><SheetDescription>{name}</SheetDescription></SheetHeader>
      <NetworkForm key={nodeId} nodeId={nodeId} control={control} />
    </SheetContent>
  </Sheet>;
}
function NetworkForm({ nodeId, control }: { nodeId: string; control: NetworkControl }) {
  const view = control.nodes.get(nodeId); const snap = view?.snapshot;
  const [confirmed, setConfirmed] = useState(false);
  const waiting = pending(view, control.now);
  const disabled = control.busy || waiting || !view;
  const current = fresh(view, control.now) && !control.error;
  const unknown = !snap?.observed || !current || waiting;
  const canChange = !!(snap?.canApply || snap?.canRestore);
  const chosenBuffer = view?.autoBufferBytes || 0;
  const optimized = !!snap?.observed && snap.congestion === "bbr" && snap.qdisc === "fq" && snap.defaultQdisc === "fq"
    && chosenBuffer > 0 && (snap.send?.[2] ?? 0) >= chosenBuffer && (snap.receive?.[2] ?? 0) >= chosenBuffer
    && snap.sendMax >= chosenBuffer && snap.receiveMax >= chosenBuffer;
  const action = async (kind: "inspect" | "apply" | "restore") => {
    if (!view) return;
    const body: Body = { action: kind, nodeId, expectedRevision: view.settings.revision || "0" };
    if (kind === "apply" || kind === "restore") { body.expected = snap?.fingerprint; body.confirm = kind === "apply" || confirmed; body.bufferBytes = kind === "apply" ? chosenBuffer : 0; }
    if (await control.run(body)) setConfirmed(false);
  };
  const command = view?.settings.command;
  const result = view?.settings.result;
  const commandText = control.busy ? "提交中…" : command ? result?.state === "failed" ? result.message : result?.state === "succeeded" ? command.action === "inspect" ? "检测完成。" : command.action === "restore" ? "已恢复原配置。" : "已应用并确认。" : waiting ? command.action === "inspect" ? "检测中…" : "正在处理…" : "结果未确认，请重新检测。" : "";
  return <div className="flex flex-col gap-4 px-4 pb-6">
    {control.error ? <p role="alert" className="text-sm text-destructive">{control.error}</p> : null}
    <div className="grid grid-cols-2 gap-2" aria-label="网络优化状态">
      <div className="rounded-md border border-border px-3 py-3">
        <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium">BBR</span><Indicator name="BBR" enabled={snap?.congestion === "bbr"} unknown={unknown} failed={false} compact /></div>
        <p className="mt-1 text-xs text-muted-foreground">{snap?.congestion || "—"}</p>
      </div>
      <div className="rounded-md border border-border px-3 py-3">
        <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium">FQ</span><Indicator name="FQ" enabled={snap?.qdisc === "fq"} unknown={unknown} failed={false} compact /></div>
        <p className="mt-1 text-xs text-muted-foreground">{snap?.qdisc || "—"}</p>
      </div>
    </div>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-xs text-muted-foreground">最近检测：{snap?.checkedAt ? new Date(snap.checkedAt).toLocaleString() : "—"}{snap && !current ? " · 未确认" : ""}</span>
      <Button variant="outline" disabled={disabled} onClick={() => void action("inspect")}>重新检测</Button>
    </div>
    {snap?.reason ? <p className="text-sm text-muted-foreground">{snap.reason}</p> : null}
    {commandText ? <p role="status" className={result?.state === "failed" ? "text-sm text-destructive" : "text-sm"}>{commandText}</p> : null}
    {canChange ? <div className="flex flex-col gap-3">
      {snap?.canApply ? <>
        <p className="text-xs text-muted-foreground">内存：{snap?.memoryBytes ? bytes(snap.memoryBytes) : "—"} · 缓冲建议：{chosenBuffer ? bytes(chosenBuffer) : "—"}（按内存）。不降低现有上限；操作可能短暂影响网络。</p>
        {!chosenBuffer ? <p className="text-xs text-muted-foreground">无法计算缓冲建议，请重新检测。</p> : null}
        <div><Button disabled={disabled || !current || !chosenBuffer} onClick={() => void action("apply")}>{optimized ? "重新优化" : "一键优化"}</Button></div>
      </> : null}
      {snap?.canRestore ? <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={confirmed} disabled={disabled || !current} onChange={event => setConfirmed(event.target.checked)} />确认恢复原配置</label>
        <Button variant="outline" disabled={disabled || !current || !confirmed} onClick={() => void action("restore")}>恢复原配置</Button>
      </div> : null}
    </div> : null}
    <details className="rounded-md border border-border">
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium">查看详情</summary>
      <div className="flex flex-col gap-4 border-t border-border px-3 py-3">
        <dl className="grid grid-cols-2 gap-2 text-sm"><dt>内核</dt><dd>{snap?.kernel || "—"}</dd><dt>检测范围</dt><dd>{snap?.scope === "host network namespace" ? "主机" : snap?.scope || "—"}</dd><dt>网卡 / MTU</dt><dd>{snap?.interface || "—"} / {snap?.mtu || "—"}</dd><dt>内存</dt><dd>{snap?.memoryBytes ? bytes(snap.memoryBytes) : "—"}</dd><dt>默认队列</dt><dd>{snap?.defaultQdisc || "—"}</dd><dt>发送 最小/默认/最大</dt><dd>{triple(snap?.send)}</dd><dt>接收 最小/默认/最大</dt><dd>{triple(snap?.receive)}</dd><dt>窗口缩放 / 接收自调</dt><dd>{snap?.observed ? `${snap.scaling} / ${snap.autoReceive}` : "—"}</dd></dl>
      </div>
    </details>
  </div>;
}
