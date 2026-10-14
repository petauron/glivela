import { useRef, useState } from "react";
import { APIError, api } from "@/api";
import { SelectControl } from "@/components/SelectControl";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { Language } from "@/translations";
import type { InstalledAppInstance } from "@/views/installed-apps-model";
import { useLanding } from "@/views/LandingControls";
import { useIPQuality } from "@/views/IPQuality";
import { bandwidthBands, linkBandwidthStatus, linkBandwidthStatusLabel } from "@/views/LinkBandwidthSummary";
import { RegionFlag } from "./RegionFlag";
import { landingLatencyColor } from "@/views/landingLatency";
import { copy } from "@/views/shared";

function speedColor(value: number) {
  return bandwidthBands.find((band) => value >= band.minimum)?.className ?? "text-muted-foreground";
}

function Speed({ value }: { value?: number }) {
  return value === undefined ? <span className="text-muted-foreground">—</span> : <span className={`font-medium tabular-nums ${speedColor(value)}`}>{value.toFixed(1)} <span className="text-xs font-normal text-muted-foreground">Mbps</span></span>;
}

export function MeridianLinkTests({ instances, language, entryId, landingId, onEntryChange, onLandingChange }: { instances: InstalledAppInstance[]; language: Language; entryId: string; landingId: string; onEntryChange: (id: string) => void; onLandingChange: (id: string) => void }) {
  const landing = useLanding();
  const quality = useIPQuality();
  const [submittingId, setSubmittingId] = useState("");
  const [notice, setNotice] = useState<{ error: boolean; text: string } | null>(null);
  const submitting = useRef(false);
  if (!landing?.view || landing.failed) return <p role="status" className="py-8 text-sm text-muted-foreground">{copy(language, landing?.failed ? "落地列表读取失败" : "正在读取落地机…", landing?.failed ? "Unable to load landing nodes" : "Loading landing nodes…")}</p>;

  const view = landing.view;
  const servers = view.servers.filter((server) => view.nodeIds.includes(server.nodeId));
  const selected = servers.find((server) => server.nodeId === landingId) ?? servers[0];
  const agents = quality?.agents ?? [];
  const destination = agents.find((agent) => agent.id === selected?.nodeId);
  const destinationReady = selected?.status === "ready" && destination?.connected && destination.capabilities.meridianLinkBandwidth;
  const destinationIssue = selected?.status !== "ready"
    ? copy(language, "落地机尚未就绪，暂不能测速。", "Landing server is not ready for testing.")
    : !destination?.connected
      ? copy(language, "落地机离线，暂不能测速。", "Landing server is offline.")
      : !destination.capabilities.meridianLinkBandwidth
        ? copy(language, "落地机 Agent 需要升级才能测速。", "Upgrade the landing Agent to run tests.")
        : view.tasksPaused
          ? copy(language, "任务已暂停，恢复后才能测速。", "Tasks are paused. Resume them before testing.")
          : "";
  const checks = quality?.diagnostics.filter((check) => check.kind === "meridian.link-bandwidth") ?? [];
  const byPair = new Map(checks.map((check) => [`${check.agentId}:${check.landingNodeId}`, check]));
  const busyNodes = new Set(quality?.diagnostics.filter((check) => linkBandwidthStatus(check) === "active").map((check) => check.agentId));
  const landingBusy = Boolean(selected && busyNodes.has(selected.nodeId));

  const start = async (nodeId: string) => {
    const source = agents.find((agent) => agent.id === nodeId);
    if (!selected || nodeId === selected.nodeId || !destinationReady || view.tasksPaused || !source?.connected || !source.capabilities.meridianLinkBandwidth || busyNodes.has(nodeId) || busyNodes.has(selected.nodeId) || quality?.loading || quality?.error || !quality || submitting.current) return;
    submitting.current = true;
    setSubmittingId(nodeId);
    setNotice(null);
    try {
      await api.checkMeridianLinkBandwidth(nodeId, selected.nodeId);
      setNotice({ error: false, text: copy(language, "测速已开始，结果会自动更新。", "Test started; results will update automatically.") });
    } catch (error) {
      setNotice({ error: true, text: error instanceof APIError && error.status === 409
        ? copy(language, "当前无法测速。请检查两端节点状态和进行中的任务。", "Cannot test now. Check both nodes and their running tasks.")
        : copy(language, "未能确认测速是否已提交。请先查看活动记录，再决定是否重试。", "Could not confirm whether the test was queued. Check Activity before retrying.") });
    } finally {
      await quality.refresh();
      submitting.current = false;
      setSubmittingId("");
    }
  };

  return <section aria-label={copy(language, "线路测速", "Link tests")} className="meridian-link-tests min-w-0 space-y-3">
    <div className="flex flex-wrap items-end gap-3">
      <div className="min-w-52 flex-1 sm:max-w-xs">
        <label className="mb-1 block text-xs font-medium text-muted-foreground">{copy(language, "落地机", "Landing server")}</label>
        <Select value={selected?.nodeId ?? null} onValueChange={(value) => { onLandingChange(value ?? ""); setNotice(null); }} items={servers.map((server) => ({ value: server.nodeId, label: server.name }))}>
          <SelectTrigger className="min-h-11 w-full md:min-h-8" aria-label={copy(language, "选择落地机", "Choose landing server")}><SelectValue placeholder={copy(language, "选择落地机", "Choose landing server")} /></SelectTrigger>
          <SelectContent><SelectGroup>{servers.map((server) => <SelectItem key={server.nodeId} value={server.nodeId}><RegionFlag code={landing.regions[server.nodeId]} language={language} />{server.name}</SelectItem>)}</SelectGroup></SelectContent>
        </Select>
      </div>
      <div className="min-w-52 flex-1 sm:max-w-xs"><label className="mb-1 block text-xs font-medium text-muted-foreground">{copy(language, "线路机", "Entry node")}</label><SelectControl aria-label={copy(language, "选择线路机", "Choose entry node")} value={entryId} onValueChange={onEntryChange} options={[{ value: "", label: copy(language, "全部线路机", "All entry nodes") }, ...instances.map((instance) => ({ value: instance.application.nodeId, label: instance.agent?.name ?? instance.application.nodeId }))]} /></div>
      <p className="pb-1 text-xs text-muted-foreground" title={copy(language, "流量随带宽变化，1 Gbps 双向合计约 2.5 GB；测试的是私网链路，不是完整代理线路。", "Traffic varies with throughput: about 2.5 GB total at 1 Gbps. This measures the private link, not the full proxy route.")}>{copy(language, "私网单线程 · 双向各 10 秒 · 结果单位 Mbps", "Private network, one stream · 10 s each way · Mbps")}</p>
    </div>
    {!servers.length ? <p className="rounded-lg border px-4 py-8 text-center text-sm text-muted-foreground">{copy(language, "尚未添加落地机", "No landing servers configured")}</p> : <>
      {(destinationIssue || landingBusy) && !quality?.loading ? <p role="status" className="text-xs text-muted-foreground">{destinationIssue || copy(language, "落地机有任务进行中，完成后可测速。", "The landing server has a running task. Test when it finishes.")} {copy(language, "历史结果仍可查看。", "Previous results remain visible.")}</p> : null}
      {quality?.error ? <p role="alert" className="text-sm text-destructive">{copy(language, "测速结果读取失败，稍后再试。", "Could not load test results. Try again later.")}</p> : null}
      {notice ? <p role={notice.error ? "alert" : "status"} className={notice.error ? "text-sm text-destructive" : "text-sm text-muted-foreground"}>{notice.text}</p> : null}
      <div className="overflow-hidden rounded-lg border bg-card">
        <div className="meridian-link-tests-header hidden items-center gap-3 border-b bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground">
          <span>{copy(language, "线路机", "Entry node")}</span><span>{copy(language, "入口 → 落地", "Entry → landing")}</span><span>{copy(language, "落地 → 入口", "Landing → entry")}</span><span>{copy(language, "延迟", "Latency")}</span><span>{copy(language, "上次测速", "Last test")}</span><span className="text-right">{copy(language, "操作", "Action")}</span>
        </div>
        {instances.filter((instance) => !entryId || instance.application.nodeId === entryId).map((instance) => {
          const nodeId = instance.application.nodeId;
          const name = instance.agent?.name ?? nodeId;
          const self = nodeId === selected.nodeId;
          const check = byPair.get(`${nodeId}:${selected.nodeId}`);
          const result = linkBandwidthStatus(check);
          const active = result === "active" || submittingId === nodeId;
          const source = agents.find((agent) => agent.id === nodeId);
          const sourceIssue = !source?.connected
            ? copy(language, "节点离线", "Node offline")
            : !source.capabilities.meridianLinkBandwidth
              ? copy(language, "Agent 待升级", "Agent update needed")
              : busyNodes.has(nodeId) && !active
                ? copy(language, "节点忙", "Node busy")
                : "";
          const canTest = Boolean(!self && destinationReady && !view.tasksPaused && source?.connected && source.capabilities.meridianLinkBandwidth && !busyNodes.has(nodeId) && !busyNodes.has(selected.nodeId) && !submitting.current && !quality?.loading && !quality?.error);
          const sample = view.latencies.find((value) => value.nodeId === nodeId && value.landingNodeId === selected.nodeId);
          const latency = sample?.state === "direct" && sample.latencyMs != null && Number.isFinite(sample.latencyMs) && sample.latencyMs >= 0 ? sample.latencyMs : undefined;
          const stamp = check?.checkedAt || check?.updatedAt;
          const stateLabel = self ? copy(language, "同一节点", "Same node") : result === "active" || submittingId === nodeId ? copy(language, "测速中…", "Testing…") : linkBandwidthStatusLabel(result, language);
          return <div key={instance.application.id} className="meridian-link-tests-row grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 border-b px-4 py-3 last:border-b-0">
            <div className="min-w-0"><div className="flex items-center gap-2"><RegionFlag code={instance.realityServices[0]?.regionCode} language={language} /><span className="truncate text-sm font-medium" title={name}>{name}</span>{!self && sourceIssue ? <span className="shrink-0 text-xs text-muted-foreground">{sourceIssue}</span> : null}</div><div className="meridian-link-tests-mobile mt-0.5 text-xs text-muted-foreground">{latency === undefined ? "—" : <span className={landingLatencyColor(latency)}>{Math.round(latency)} ms</span>}{stamp ? ` · ${new Date(stamp).toLocaleString(language, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" })}` : ""}</div></div>
            <div className="meridian-link-tests-value col-start-1 row-start-2 text-xs">{!self && result === "succeeded" && check?.link ? <><span className="meridian-link-tests-mobile text-muted-foreground">{copy(language, "去", "Out")} </span><Speed value={check.link.uploadMbps} /></> : <span className={["failed", "non_direct", "identity_changed"].includes(result) ? "text-destructive" : "text-muted-foreground"}>{stateLabel}</span>}</div>
            <div className="meridian-link-tests-value col-start-1 row-start-3 text-xs">{!self && result === "succeeded" && check?.link ? <><span className="meridian-link-tests-mobile text-muted-foreground">{copy(language, "回", "Back")} </span><Speed value={check.link.downloadMbps} /></> : null}</div>
            <span className={`meridian-link-tests-desktop hidden text-xs tabular-nums ${landingLatencyColor(latency)}`}>{latency === undefined ? "—" : `${Math.round(latency)} ms`}</span>
            <time className="meridian-link-tests-desktop hidden text-xs text-muted-foreground" dateTime={stamp ?? ""}>{stamp ? new Date(stamp).toLocaleString(language, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—"}</time>
            <Button type="button" variant="outline" size="sm" className="meridian-link-tests-action col-start-2 row-span-3 min-h-11" disabled={!canTest} aria-label={copy(language, `测试 ${name} 到 ${selected.name} 的带宽`, `Test bandwidth from ${name} to ${selected.name}`)} onClick={() => void start(nodeId)}>{active ? copy(language, "测速中", "Testing") : copy(language, "测速", "Test")}</Button>
          </div>;
        })}
        {!instances.length ? <p className="px-4 py-8 text-center text-sm text-muted-foreground">{copy(language, "没有匹配的线路机", "No matching entry nodes")}</p> : null}
      </div>
    </>}
  </section>;
}
