import { useCallback, useEffect, useRef, useState } from "react";

type LatencySample = { checkedAt: string; latencyMs?: number; samples: number };
export type RouteLatency = { history?: LatencySample[]; historyUnavailable?: boolean; entryId: string; landingId: string; port: number; state: "unknown" | "pending" | "ready" | "unreachable" | "stale" | "unavailable"; checkedAt?: string; latencyMs?: number; samples: number };
type Loader = (body: { refresh: boolean; force: boolean }, signal: AbortSignal) => Promise<{ latencies: RouteLatency[] }>;
export const latencyKey = (entry: string, landing: string, port = 1080) => `${entry}/${landing}/${port}`;
const formatLatency = (value: number) => value > 0 && value < 0.1 ? "<0.1 ms" : value > 0 && value < 1 ? `${value.toFixed(1)} ms` : `${Math.round(value)} ms`;

// Only the visible control page requests diagnostics. Samples are shared by
// entry/landing/port, never measured again for each account or table row.
export function useRouteLatencies(enabled: boolean, load: Loader) {
  const [values, setValues] = useState<RouteLatency[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [now, setNow] = useState(Date.now());
  const request = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const lastQueued = useRef(0);
  const refresh = useCallback(async (force = false) => {
    if (!enabled || document.hidden || request.current) return;
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    const started = Date.now();
    const queue = force || started - lastQueued.current >= 60_000;
    try {
      const next = await load({ refresh: queue, force }, controller.signal);
      if (!controller.signal.aborted) {
        setValues(next.latencies); setError(""); setNow(Date.now());
        if (queue) lastQueued.current = started;
      }
    } catch {
      if (!controller.signal.aborted) setError("延迟刷新失败，已有结果可能过期；不影响线路配置。");
    } finally {
      if (request.current === controller) {
        request.current = null;
        if (mounted.current) setBusy(false);
      }
    }
  }, [enabled, load]);
  useEffect(() => {
    mounted.current = true;
    if (!enabled) return () => { mounted.current = false; };
    void refresh();
    const visible = () => {
      if (document.hidden) request.current?.abort();
      else void refresh();
    };
    const timer = window.setInterval(() => { setNow(Date.now()); void refresh(); }, 5_000);
    document.addEventListener("visibilitychange", visible);
    return () => { mounted.current = false; window.clearInterval(timer); document.removeEventListener("visibilitychange", visible); request.current?.abort(); request.current = null; };
  }, [enabled, refresh]);
  return { values: new Map(values.map(value => [latencyKey(value.entryId, value.landingId, value.port), value])), busy, error, now, refresh };
}

export function LatencyCell({ value, now, failed = false, hideEmpty = false }: { value?: RouteLatency; now: number; failed?: boolean; hideEmpty?: boolean }) {
  value ??= { entryId: "", landingId: "", port: 1080, state: "unknown", samples: 0 };
  const history = (value.history ?? []).slice(-10);
  const lastHistory = history[history.length - 1];
  const checked = value.checkedAt ? Date.parse(value.checkedAt) : lastHistory ? Date.parse(lastHistory.checkedAt) : NaN;
  const stale = failed || value.state === "stale" || Number.isFinite(checked) && now - checked > 120_000;
  const currentLatency = value.latencyMs;
  const historyLatency = lastHistory && lastHistory.samples > 0 ? lastHistory.latencyMs : undefined;
  const hasCurrent = currentLatency != null && Number.isFinite(currentLatency) && currentLatency >= 0;
  const hasHistory = historyLatency != null && Number.isFinite(historyLatency) && historyLatency >= 0;
  const fromHistory = !hasCurrent && !value.checkedAt && value.state !== "unreachable" && hasHistory;
  const latency = hasCurrent ? currentLatency : fromHistory ? historyLatency : undefined;
  const hasValue = latency != null;
  const historical = fromHistory || stale || value.state === "unavailable" || value.state === "pending";
  const high = latency != null && latency > 100;
  const lastFailed = !hasCurrent && (value.state === "unreachable" || (value.checkedAt ? value.samples === 0 : lastHistory?.samples === 0));
  const label = value.state === "unavailable" ? "节点离线或暂停" : stale ? "已过期" : value.state === "pending" ? "正在检测…" : value.state === "unreachable" ? "不可达（3 次失败）" : value.state === "unknown" ? "尚未检测" : "";
  const tone = stale || value.state === "unavailable" || value.state === "unknown" || value.state === "pending" ? "muted" : value.state === "unreachable" ? "failure" : high ? "slow" : hasValue ? "fast" : "muted";
  const measuredAt = value.checkedAt ?? lastHistory?.checkedAt;
  const latencyText = hasValue ? `${historical ? "上次 " : ""}${formatLatency(latency!)}` : lastFailed ? `${historical ? "上次" : ""}失败` : "—";
  const status = [value.state === "pending" ? "正在检测" : "", value.state === "unavailable" ? "节点离线或暂停" : "", failed ? "刷新失败" : "", stale ? "结果已过期" : ""].filter(Boolean).join("；");
  const latencyTitle = `延迟 ${latencyText}${measuredAt ? `；检测时间：${new Date(measuredAt).toLocaleString()}` : ""}${status ? `；${status}` : label ? `；${label}` : ""}`;
  const slots: (LatencySample | null)[] = [...Array.from({ length: Math.max(0, 10 - history.length) }, () => null), ...history];
  const attempts = history.length * 3;
  const failures = history.reduce((total, sample) => total + 3 - sample.samples, 0);
  const failureRate = attempts ? `${(failures * 100 / attempts).toFixed(1)}%` : "—";
  if (hideEmpty && !hasValue && !lastFailed && history.length === 0 && value.state !== "pending") return <span className="gl-secondary" aria-label="暂无延迟数据">—</span>;
  const cells = (kind: "latency" | "failure") => <div className="gl-latency-cells" role="list" aria-label={kind === "latency" ? "最近十轮 TCP 延迟，最旧到最新" : "最近十轮 TCP 建连失败率，最旧到最新"}>
    {slots.map((sample, index) => {
      const success = sample != null && sample.samples > 0 && typeof sample.latencyMs === "number" && Number.isFinite(sample.latencyMs);
      const at = sample ? new Date(sample.checkedAt).toLocaleString() : "";
      const metric = sample ? kind === "failure" ? (3 - sample.samples) * 100 / 3 : success ? sample.latencyMs! : null : null;
      const detail = metric === null ? sample && kind === "latency" && sample.samples === 0 ? "失败" : "N/A" : kind === "failure" ? `${metric.toFixed(1)}%` : formatLatency(metric);
      const limits = kind === "failure" ? [1, 3, 6, 9] : [60, 100, 160, 200];
      const bucket = metric === null ? "empty" : String(Math.max(0, limits.findIndex(limit => metric <= limit)) || 0);
      const tone = kind === "latency" && sample && sample.samples === 0 || metric !== null && metric > limits[limits.length - 1]! ? "4" : bucket;
      const description = `${at ? `${at}：` : ""}${kind === "failure" ? "TCP 建连失败率" : "延迟"} ${detail}`;
      return <span key={sample ? `${sample.checkedAt}-${index}` : `empty-${index}`} className="gl-latency-cell" data-tone={tone} role="listitem" tabIndex={sample ? 0 : undefined} aria-label={description}><span className="gl-latency-tooltip" aria-hidden="true"><span>{at || "暂无数据"}</span><strong>{detail}</strong></span></span>;
    })}
  </div>;
  return <div className="gl-latency-summary" data-single={history.length === 0 ? "true" : undefined} data-inactive={stale || value.state === "unavailable" ? "true" : undefined} title="入口到落地 TCP 建连；失败率按最近检测的连接次数计算，不等于 ICMP 丢包率。">
    <div className="gl-latency-column">
      <div className="gl-latency-heading"><span>延迟</span><i aria-hidden="true" /><span className="gl-latency-value" data-tone={tone} title={latencyTitle} aria-label={latencyTitle}>{!hasValue && value.state === "pending" ? "检测中" : latencyText}</span></div>
      {history.length ? cells("latency") : null}
    </div>
    {history.length ? <div className="gl-latency-column">
      <div className="gl-latency-heading"><span title="按最近 TCP 建连失败次数计算，不是 ICMP 丢包率">失败</span><i aria-hidden="true" /><span className="gl-latency-value" data-tone={stale || value.state === "unavailable" ? "muted" : failures ? "failure" : attempts ? "fast" : "muted"}>{failureRate}</span></div>
      {cells("failure")}
    </div> : null}
    {label ? <span className="sr-only" role="status">{label}</span> : null}
  </div>;
}
