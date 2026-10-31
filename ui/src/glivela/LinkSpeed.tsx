import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { FieldSet, FieldLegend } from "@/components/ui/field";
import { SelectControl } from "@/components/SelectControl";

type Mode = "direct" | "ss2022";
type Sample = { mbps: number; bytes: number; sentBytes: number; seconds: number; retransmits?: number };
type Measurement = { upload: Sample | null; download: Sample | null; uploadError?: string; downloadError?: string; error?: string };
type Progress = { role: string; receivedAt?: string; runningAt?: string; finishedAt?: string; confirmedAt?: string };
type SpeedPolicy = { durationSeconds: number; warmupSeconds: number; perNodeBytes?: number; perDirectionBytes?: number };
type SpeedPoint = { mode: Mode; direction: "upload" | "download"; sequence: number; mbps: number; seconds: number };
export type SpeedTest = { phase: string; progress?: Progress[]; points?: SpeedPoint[]; id: string; entryId: string; landingId: string; modes: Mode[]; state: string; startedAt: string; finishedAt?: string; direct: Measurement | null; ss2022: Measurement | null; error?: string; cleanupConfirmed: boolean; entryWireBytes?: number; landingWireBytes?: number; policy?: SpeedPolicy };
export type SpeedList = { channels: { id: string; connected: boolean }[]; revision: string; tests: SpeedTest[]; policy?: SpeedPolicy };
export type SpeedBody = { afterRevision?: string; start?: { id: string; entryId: string; landingId: string; modes: Mode[] } };
type Loader = (body: SpeedBody, signal?: AbortSignal) => Promise<SpeedList>;

const stateLabel: Record<string, string> = { queued: "等待节点", running: "测速中", cleaning: "清理中", completed: "已完成", failed: "失败" };
const phaseLabel: Record<string, string> = { receiver: "落地准备", client: "线路测速", "client-cleanup": "线路清理", cleanup: "落地清理" };
const errors: Record<string, string> = {
 control_disconnected: "测速通道未连接，请确认两端 Glivela 已更新并在线。",
 pair_unavailable: "当前配对未启用、尚未就绪，或没有已授权的公网 SS2022 地址。",
 test_busy_or_cleanup_pending: "另有测速运行中或等待清理确认，请稍后再试。",
 latency_above_100ms: "线路参考延迟超过 100ms，无法开始测速。",
 iperf3_not_installed: "节点的 Glivela 安装包缺少测速工具，请更新或修复节点端。",
 iperf3_unavailable: "节点的测速工具未通过校验，请修复节点端安装。",
 iperf3_version_invalid: "节点的测速工具版本不匹配，请更新节点端。",
 iperf3_3_17_required: "节点需要支持认证的 iperf3 3.17 或更新版本。",
 iperf3_authentication_required: "节点的 iperf3 未启用认证支持。",
 insufficient_memory_or_disk: "节点的可用内存或临时磁盘空间不足。",
 host_firewall_requires_authorization: "现有主机防火墙不支持安全的临时放行。",
 lease_expired_cleanup_unconfirmed: "任务超时，尚未收到完整清理确认。",
 client_cleanup_unconfirmed: "线路端清理尚未确认。",
 controller_restarted: "控制端重启，本轮未继续执行；正在核对清理状态。",
 interrupted_execution: "节点执行进程中断，本轮不会自动重跑。",
 receiver_cleanup_unconfirmed: "落地端清理尚未确认。",
 iperf_transfer_failed: "测速传输失败或超时。",
 iperf_output_invalid: "测速输出无法解析。",
 iperf_result_missing: "测速未返回最终结果。",
 iperf_result_bytes_invalid: "测速结果缺少有效的传输字节数。",
 iperf_result_duration_invalid: "测速结果的时长不符合要求。",
 iperf_result_rate_invalid: "测速结果的速度与接收字节数不一致。",
 iperf_result_invalid: "测速结果无效。",
 iperf_transfer_failed_or_budget_exhausted: "传输失败、超时或达到本轮流量上限。",
 speed_budget_exceeded: "本轮或某项测速达到流量上限，整轮已中止，未完成的项目没有结果。",
 configuration_or_identity_changed: "节点身份或配置已变化，本轮未执行。",
 pair_identity_or_configuration_changed: "线路配置或授权已变化，本轮已停止。",
};
const describe = (error: string) => errors[error] ?? `未完成（${error}）`;
export const speedKey = (entryId: string, landingId: string) => `${entryId}/${landingId}`;
const inProgress = (test: SpeedTest) => ["queued", "running", "cleaning"].includes(test.state);

// One shared event stream supplies the route list and the selected details.
// Leaving the page cancels the wait, while an already submitted task continues
// on the controller and is recovered when the page becomes visible again.
export function useLinkSpeed(request: Loader, visible: boolean) {
 const [data, setData] = useState<SpeedList>({ revision: "0", tests: [], channels: [] });
 const [submitting, setSubmitting] = useState(false);
 const [error, setError] = useState<{ pair: string; message: string }>();
 const [connectionError, setConnectionError] = useState("");
 const [displayedAt, setDisplayedAt] = useState("");
 const pending = useRef(false);
 const mounted = useRef(false);
 const alive = useRef(false);
 useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
 useEffect(() => {
  mounted.current = true;
  if (!visible) return () => { mounted.current = false; };
  const controller = new AbortController(); let revision: string | undefined;
  let backoff = 1000;
  const run = async () => {
   while (!controller.signal.aborted) {
    if (document.hidden) {
     await new Promise<void>(resolve => {
      const wake = () => { document.removeEventListener("visibilitychange", wake); controller.signal.removeEventListener("abort", wake); resolve(); };
      document.addEventListener("visibilitychange", wake); controller.signal.addEventListener("abort", wake, { once: true });
     });
     if (controller.signal.aborted) break;
     if (document.hidden) continue;
    }
    try {
     const result = await request(revision == null ? {} : { afterRevision: revision }, controller.signal);
     if (controller.signal.aborted) break;
     if (!/^\d+$/.test(result.revision ?? "")) throw new Error("任务事件协议不支持，请更新控制端。");
     revision = result.revision; backoff = 1000;
     setData(previous => BigInt(result.revision) >= BigInt(previous.revision) ? result : previous);
     setDisplayedAt(new Date().toISOString()); setConnectionError("");
    } catch (failure) {
     if (controller.signal.aborted) break;
     setConnectionError(failure instanceof Error ? failure.message : "任务连接中断，正在重新连接；保留已有结果，请勿重复提交。");
     await new Promise<void>(resolve => {
      const wake = () => { window.clearTimeout(timer); controller.signal.removeEventListener("abort", wake); resolve(); };
      const timer = window.setTimeout(wake, backoff); controller.signal.addEventListener("abort", wake, { once: true });
     });
     backoff = Math.min(backoff * 2, 10000);
    }
   }
  };
  void run();
  return () => { mounted.current = false; controller.abort(); };
 }, [request, visible]);
 const busy = data.tests.some(inProgress);
 const latest = useMemo(() => {
  const result = new Map<string, SpeedTest>();
  for (const test of data.tests) { const id = speedKey(test.entryId, test.landingId); if (!result.has(id)) result.set(id, test); }
  return result;
 }, [data.tests]);
 const start = useCallback(async (entryId: string, landingId: string, modes: Mode[]) => {
  if (!visible || pending.current || busy || modes.length === 0) return false;
  pending.current = true; setSubmitting(true); setError(undefined);
  const pair = speedKey(entryId, landingId);
  try {
   const result = await request({ start: { id: crypto.randomUUID(), entryId, landingId, modes } });
   if (!/^\d+$/.test(result.revision ?? "")) throw new Error("任务事件协议不支持，请更新控制端。");
   if (mounted.current) { setData(previous => BigInt(result.revision) >= BigInt(previous.revision) ? result : previous); setDisplayedAt(new Date().toISOString()); }
   return true;
  } catch (failure) {
   if (mounted.current) setError({ pair, message: failure instanceof Error ? describe(failure.message) : "未能确认任务是否提交，请刷新确认后再操作。" });
   return false;
  } finally { pending.current = false; if (alive.current) setSubmitting(false); }
 }, [busy, request, visible]);
 return { data, latest, busy, submitting, error, connectionError, displayedAt, start };
}
export type LinkSpeedControl = ReturnType<typeof useLinkSpeed>;

function sampleLabel(sample: Sample | null | undefined) { return sample ? (sample.mbps / 8).toFixed(1) : "—"; }
function trafficLabel(bytes: number | undefined) { return bytes == null ? "—" : bytes >= 1e9 ? `${(bytes / 1e9).toFixed(2)} GB` : `${(bytes / 1e6).toFixed(2)} MB`; }
function trafficPolicy(policy: SpeedPolicy | undefined) {
 if (!policy) return "";
 if (policy.perDirectionBytes && policy.perNodeBytes) return ` · 每项限 ${trafficLabel(policy.perDirectionBytes)} · 每轮限 ${trafficLabel(policy.perNodeBytes)} / 节点`;
 if (policy.perDirectionBytes) return ` · 每项限 ${trafficLabel(policy.perDirectionBytes)} / 节点`;
 if (policy.perNodeBytes) return ` · 每轮限 ${trafficLabel(policy.perNodeBytes)} / 节点`;
 return " · 无流量上限";
}
// Match the existing bandwidth bands (in Mbps); values are displayed in MB/s.
function speedBand(sample: Sample) {
 if (!Number.isFinite(sample.mbps) || sample.mbps < 0) return { tone: "unknown", range: "未确认" };
 if (sample.mbps >= 500) return { tone: "excellent", range: "≥62.5 MB/s" };
 if (sample.mbps >= 100) return { tone: "good", range: "12.5–<62.5 MB/s" };
 if (sample.mbps >= 10) return { tone: "fair", range: "1.25–<12.5 MB/s" };
 return { tone: "poor", range: "<1.25 MB/s" };
}
function speedBandTitle(sample: Sample) { return `速度分档：${speedBand(sample).range}（按未四舍五入的数值）`; }
function SpeedBars({ points, max, label, compact = false, emptyText = "等待数据", slots = 8 }: { points: SpeedPoint[]; max: number; label: string; compact?: boolean; emptyText?: string; slots?: number }) {
 const count = Math.max(1, Math.min(10, slots));
 const values = points.filter(point => point.sequence > 0 && point.sequence <= count).sort((a, b) => a.sequence - b.sequence);
 if (!values.length && compact) return null;
 const description = values.length ? values.map(point => `第 ${point.sequence} 段 ${(point.mbps / 8).toFixed(1)} MB/s，${point.seconds.toFixed(1)} 秒`).join("；") : emptyText;
 return <div className={compact ? "gl-speed-bars gl-speed-bars-compact" : "gl-speed-bars"} role="img" aria-label={`${label}：${description}`} title={`${label}：${description}`}>
  <div className="gl-speed-grid" aria-hidden="true" style={{gridTemplateColumns:`repeat(${count}, minmax(0, 1fr))`}}>{Array.from({length:count}, (_, index)=><i key={index}/>)}</div>
  {values.map(point => <span className="gl-speed-column" key={point.sequence} style={{width:`${100 / count}%`, left:`${(point.sequence - 1) * 100 / count}%`}}><span className="gl-speed-bar" style={{transform:`scaleY(${Math.max(.02, Math.min(1, point.mbps / max))})`}}/></span>)}
  {!values.length?<span className="gl-speed-bars-empty" aria-hidden="true">{emptyText}</span>:null}
 </div>;
}

// The summary belongs to the entry/landing pair, so multiple account routes
// using that pair deliberately display the same measurement.
export function RouteSpeedSummary({ test }: { test?: SpeedTest }) {
 if (!test) return <span className="gl-secondary" aria-label="暂无测速数据">—</span>;
 if (inProgress(test)) return <span className="gl-secondary">{stateLabel[test.state]}</span>;
 const modes = ([ ["直连", test.direct, test.modes.includes("direct")], ["加密", test.ss2022, test.modes.includes("ss2022")] ] as const)
  .filter(([, measurement, selected]) => selected && !!measurement && !!(measurement.upload || measurement.download || measurement.uploadError || measurement.downloadError || measurement.error));
 if (!modes.length) return test.state === "failed" ? <span className="gl-secondary">测速失败</span> : <span className="gl-secondary" aria-label="暂无测速数据">—</span>;
 return <div className="gl-speed-summary" aria-label={test.state === "failed" ? "线路测速结果，本轮未完成" : "线路测速结果"}>
  {modes.map(([name, measurement]) => {
   const upload = measurement?.upload, download = measurement?.download;
   const directionFailed = !!measurement?.uploadError || !!measurement?.downloadError;
   const mode: Mode = name === "直连" ? "direct" : "ss2022";
   const slots = Math.max(1, Math.min(10, test.policy?.durationSeconds ?? 8));
   const points = (test.points ?? []).filter(point => point.mode === mode && point.sequence > 0 && point.sequence <= slots);
   const max = Math.max(1, ...points.map(point => point.mbps));
   const accessible = [upload ? `线路到落地 ${sampleLabel(upload)} MB/s` : measurement?.uploadError ? "上传失败" : "", download ? `落地到线路 ${sampleLabel(download)} MB/s` : measurement?.downloadError ? "下载失败" : "", measurement?.error ? "测速未完成" : ""].filter(Boolean).join("，");
   return <span key={name}><span title={name === "加密" ? "使用 SS2022 加密通道" : "公网直连"}>{name}</span><strong title="↑ 线路到落地；↓ 落地到线路" aria-label={`${name}，${accessible || "测速失败"}`}>
    {upload?<span className="gl-speed-value" data-tone={speedBand(upload).tone} title={speedBandTitle(upload)}>↑{sampleLabel(upload)}{directionFailed ? " MB/s" : ""}</span>:measurement?.uploadError?<span title={describe(measurement.uploadError)}>↑失败</span>:null}{(upload||measurement?.uploadError)&&(download||measurement?.downloadError)?" ":null}{download?<span className="gl-speed-value" data-tone={speedBand(download).tone} title={speedBandTitle(download)}>↓{sampleLabel(download)}{directionFailed ? " MB/s" : ""}</span>:measurement?.downloadError?<span title={describe(measurement.downloadError)}>↓失败</span>:null}{upload||download?`${directionFailed ? "" : " MB/s"}${measurement?.error ? " · 未完成" : ""}`:directionFailed?null:"失败"}
   </strong>{points.length?<span className="gl-speed-sparks"><SpeedBars compact slots={test.policy?.durationSeconds ?? 8} points={points.filter(point=>point.direction==="upload")} max={max} label={`${name}上传`}/><SpeedBars compact slots={test.policy?.durationSeconds ?? 8} points={points.filter(point=>point.direction==="download")} max={max} label={`${name}下载`}/></span>:null}</span>;
  })}
  {test.state === "failed"?<small>本轮未完成</small>:null}
 </div>;
}

export function LinkSpeed({ entryId, entryName, landingId, landingName, reason, disabled, control }: {
 entryId: string; entryName: string; landingId: string; landingName: string; reason?: string; disabled: boolean; control: LinkSpeedControl;
}) {
 const [direct, setDirect] = useState(true);
 const [ss2022, setSS2022] = useState(true);
 const [selectedId, setSelectedId] = useState<string>();
 const pair = speedKey(entryId, landingId);
 const history = control.data.tests.filter(item => item.entryId === entryId && item.landingId === landingId);
 const latest = control.latest.get(pair);
 const test = history.find(item => item.id === selectedId) ?? latest;
 const historical = !!test && test.id !== latest?.id;
 const policy = control.data.policy;
 const channels = new Map(control.data.channels.map(channel => [channel.id, channel.connected]));
 const channelText = !channels.has(entryId) || !channels.has(landingId) ? "正在确认测速通道" : channels.get(entryId) && channels.get(landingId) ? "两端测速通道已连接" : "测速通道未连接";
 const unavailable = reason || (channelText === "测速通道未连接" ? "测速通道未连接，请确认两端 Glivela 已更新并在线。" : "");
 const start = async () => {
  if (await control.start(entryId, landingId, [...(direct ? ["direct" as const] : []), ...(ss2022 ? ["ss2022" as const] : [])])) setSelectedId(undefined);
 };
 return <section className="gl-route-speed" aria-label={`${landingName}线路测速`}>
  <h3>线路测速</h3>
  <div className="gl-speed-endpoints" aria-label="测速两端">
   <div><span>发起端 · 线路机</span><strong>{entryName}</strong></div><span aria-hidden="true">→</span><div><span>接收端 · 落地机</span><strong>{landingName}</strong></div>
  </div>
  <dl className="gl-speed-parameters" aria-label="当前测速参数">
   <div><dt>协议</dt><dd>TCP</dd></div><div><dt>并发流</dt><dd>1</dd></div><div><dt>测量时长</dt><dd>{policy ? `${policy.durationSeconds} 秒` : "待获取"}</dd></div><div><dt>预热</dt><dd>{policy ? `${policy.warmupSeconds} 秒` : "待获取"}</dd></div>
  </dl>
  <p className="gl-speed-help">固定参数 · 依次测上行和下行；上行为线路机 → 落地机，下行为落地机 → 线路机。</p>
  <form onSubmit={event => { event.preventDefault(); void start(); }}>
   <FieldSet className="gl-speed-modes" disabled={disabled || control.submitting || control.busy}>
    <FieldLegend>测速方式</FieldLegend>
    <label><Checkbox checked={direct} onCheckedChange={setDirect}/>公网直连</label>
    <label><Checkbox checked={ss2022} onCheckedChange={setSS2022}/>SS2022 加密</label>
   </FieldSet>
   <Button className="gl-wide" type="submit" disabled={disabled || control.submitting || control.busy || !!unavailable || !direct && !ss2022}>{control.submitting ? "正在提交…" : control.busy ? latest && inProgress(latest) ? "测速进行中…" : "其他线路测速中" : "开始测速"}</Button>
  </form>
  <p className="gl-speed-channel">{channelText}</p>
  {unavailable ? <p className="gl-speed-error">{unavailable}</p> : null}
  {control.error?.pair === pair ? <p className="gl-speed-error" role="alert">{control.error.message}</p> : null}
  {control.connectionError ? <p className="gl-speed-error" role="status">{control.connectionError} 已有结果保留。</p> : null}
  <div className="gl-speed-result-heading"><h4>{historical ? "历史结果" : "实时结果"}</h4>{historical ? <Button type="button" size="sm" variant="ghost" onClick={() => setSelectedId(undefined)}>回到最新</Button> : null}</div>
  {test ? <SpeedWindow key={test.id} test={test}/> : <p className="gl-speed-empty">该配对尚未测速。</p>}
  <div className="gl-speed-history" aria-label={`${landingName}测速历史`}>
   <h4>历史记录 <small>{history.length} 条</small></h4>
   {history.length ? <ol>{history.map(item => <li key={item.id}><Button type="button" variant="ghost" className="gl-speed-history-item" aria-pressed={item.id === test?.id} onClick={() => setSelectedId(item.id)}>
    <span><time dateTime={item.startedAt}>{new Date(item.startedAt).toLocaleString()}</time><small>{speedState(item)} · {item.modes.map(mode => mode === "direct" ? "直连" : "SS2022").join(" / ")}</small></span>
    <span className="gl-speed-history-rates">{item.modes.map(mode => { const value = mode === "direct" ? item.direct : item.ss2022; return <span key={mode}>{mode === "direct" ? "直连" : "加密"} ↑{sampleLabel(value?.upload)} ↓{sampleLabel(value?.download)} MB/s</span>; })}</span>
   </Button></li>)}</ol> : <p className="gl-speed-empty">完成测速后，可在这里回看该配对的记录。</p>}
  </div>
 </section>;
}

function speedState(test: SpeedTest) {
 return test.state === "completed" && !test.cleanupConfirmed ? "结果已返回，清理待确认" : stateLabel[test.state] ?? "状态未知";
}

function SpeedWindow({ test }: { test: SpeedTest }) {
 const [selectedSeries, setSelectedSeries] = useState("");
 const choices = test.modes.flatMap(mode => (["upload", "download"] as const).map(direction => ({ value: `${mode}/${direction}`, label: `${mode === "direct" ? "公网直连" : "SS2022 加密"} · ${direction === "upload" ? "↑ 上行" : "↓ 下行"}` })));
 const running = inProgress(test);
 const live = test.points?.at(-1);
 const following = running && test.phase === "client" && live ? `${live.mode}/${live.direction}` : choices[0]?.value;
 const seriesKey = choices.some(choice => choice.value === selectedSeries) ? selectedSeries : following;
 const [mode, direction] = (seriesKey ?? "direct/upload").split("/") as [Mode, "upload" | "download"];
 const measurement = mode === "direct" ? test.direct : test.ss2022;
 const result = measurement?.[direction];
 const directionError = direction === "upload" ? measurement?.uploadError : measurement?.downloadError;
 const slots = Math.max(1, Math.min(10, test.policy?.durationSeconds ?? 8));
 const points = (test.points ?? []).filter(point => point.mode === mode && point.direction === direction && point.sequence > 0 && point.sequence <= slots);
 const peak = points.length ? Math.max(...points.map(point => point.mbps)) : undefined;
 const active = running && test.phase === "client" && live?.mode === mode && live.direction === direction ? live : undefined;
 const failed = !!directionError || !!measurement?.error && !result;
 const current = result ? `${sampleLabel(result)} MB/s` : active && active.sequence > 0 ? `${(active.mbps / 8).toFixed(1)} MB/s` : "—";
 return <div className="gl-speed-window">
  <div className="gl-speed-result-status"><span role="status">{speedState(test)}</span><time dateTime={test.startedAt}>{new Date(test.startedAt).toLocaleString()}</time></div>
  <SelectControl aria-label="查看测速方式和方向" options={choices} value={seriesKey ?? ""} onValueChange={setSelectedSeries}/>
  <div className="gl-speed-chart" aria-label="测速图表与摘要">
   <div className="gl-speed-chart-label"><strong>{current}</strong><span>{result ? "接收端平均" : active?.sequence === 0 ? "预热中" : failed ? "未完成" : running ? "实时采样" : "无测量结果"}</span></div>
   <SpeedBars points={points} max={Math.max(1, peak ?? 1)} label={choices.find(choice => choice.value === seriesKey)?.label ?? "测速"} slots={slots} emptyText={running ? "等待实际采样" : failed ? "本方向未完成" : "无逐秒记录"}/>
   <dl className="gl-speed-metrics" aria-label="结果摘要">
    <div><dt>平均 MB/s</dt><dd>{sampleLabel(result)}</dd></div><div><dt>采样峰值 MB/s</dt><dd>{peak == null ? "—" : (peak / 8).toFixed(1)}</dd></div><div><dt>TCP 重传</dt><dd>{result?.retransmits?.toLocaleString() ?? "—"}</dd></div><div><dt>接收数据</dt><dd>{result ? trafficLabel(result.bytes) : "—"}</dd></div>
   </dl>
  </div>
  <p className="gl-speed-window-note">每格约一秒，预热不计入图表。平均为接收端结果；{mode === "ss2022" ? "重传为内层 TCP，不能视为公网丢包率。" : "重传次数不是丢包率。"}</p>
  <p className="gl-speed-window-note">本轮流量：线路 {trafficLabel(test.entryWireBytes)} / 落地 {trafficLabel(test.landingWireBytes)}{trafficPolicy(test.policy)}</p>
  {test.progress?.length ? <details className="gl-context-details gl-speed-phases"><summary>执行进度与清理</summary>{test.progress.map(progress => <p className="gl-speed-progress" key={progress.role}>{phaseLabel[progress.role] ?? progress.role} · {progress.confirmedAt ? "结果已确认" : progress.runningAt ? "执行中" : "已接收"}</p>)}<p className="gl-speed-progress">临时资源清理：{test.cleanupConfirmed ? "已确认" : "尚未确认"}</p></details> : null}
  {[test.error, measurement?.error, directionError].filter((error, index, all) => !!error && all.indexOf(error) === index).map(error => <p className="gl-speed-error" key={error}>{describe(error!)}</p>)}
 </div>;
}
