import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LockKeyhole, LockKeyholeOpen, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AssessmentBadge, AssessmentSummary } from "../views/IPAssessment";
import { useControlRequest } from "./ControlAccess";
import { qualityCategories, qualityHistory, qualityRecords, qualityStates, serviceResult, unlockSummary, type QualityRecord, type QualityResults, type QualityTarget } from "./quality-model";

const errors: Record<string, string> = { timeout: "检测超时", docker_unavailable: "节点未准备好已审核的检测镜像或 Docker 不可用", download_failed: "固定版本检测镜像未能下载", invalid_report: "检测未返回匹配此 IP 的有效报告", ip_changed: "实际出口 IP 已变化", detection_failed: "检测或容器清理未确认", target_changed: "节点配置或目标已变化", interrupted: "检测已中断" };

export function useIPQuality(active: boolean) {
  const request = useControlRequest();
  const [results, setResults] = useState<QualityResults>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const refresh = useCallback(async (signal?: AbortSignal) => {
    setResults(await request<QualityResults>("ip-quality", {}, signal));
    setError("");
  }, [request]);
  const checking = results?.checks.some(check => check.state === "pending" || check.state === "running") ?? false;
  useEffect(() => {
    if (!active) return;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try { await refresh(abort.signal); }
      catch (failure) { if (!abort.signal.aborted) setError(failure instanceof Error ? failure.message : "读取评测失败"); }
      finally { if (!abort.signal.aborted) timer = setTimeout(() => void load(), checking ? 1000 : 5000); }
    };
    void load();
    return () => { abort.abort(); clearTimeout(timer); };
  }, [active, refresh, checking]);
  const startCheck = async (target: QualityTarget) => {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError("");
    try { setResults(await request<QualityResults>("ip-quality", { nodeId: target.nodeId, address: target.address })); }
    catch (failure) { setError(failure instanceof Error ? failure.message : "检测未提交"); }
    finally { pending.current = false; setBusy(false); }
  };
  const records = useMemo(() => qualityRecords(results), [results]);
  const reload = () => void refresh().catch(failure => setError(failure instanceof Error ? failure.message : "读取失败"));
  return { results, records, error, busy, startCheck, reload };
}
export type QualityControl = ReturnType<typeof useIPQuality>;

export function UnlockSummary({ record }: { record: QualityRecord }) {
  const summary = unlockSummary(record.check?.report);
  const history = qualityHistory(record);
  const Icon = summary.count ? LockKeyholeOpen : LockKeyhole;
  return <span className="gl-unlock-summary" data-tone={history ? "muted" : summary.count === summary.total ? "good" : summary.count ? "warning" : "muted"}>
    <Icon aria-hidden="true"/><span>{history ? "历史 · " : ""}{summary.label}{record.check?.report ? ` ${summary.count}/${summary.total}` : ""}</span>
  </span>;
}

function UnlockDetails({ record }: { record: QualityRecord }) {
  const report = record.check?.report;
  return <Tabs defaultValue="streaming" className="gl-unlock-details">
    <TabsList aria-label="解锁服务分类">{qualityCategories.map(category => {
      const count = category.services.filter(meta => serviceResult(report?.services.find(service => service.name === meta.name)).unlocked).length;
      return <TabsTrigger key={category.id} value={category.id}>{category.label} {count}/{category.services.length}</TabsTrigger>;
    })}</TabsList>
    {qualityCategories.map(category => <TabsContent key={category.id} value={category.id}>
      <table className="gl-unlock-table"><thead><tr><th>服务</th><th>检测结果</th><th>地区</th></tr></thead><tbody>{category.services.map(meta => {
        const service = report?.services.find(item => item.name === meta.name);
        const result = serviceResult(service);
        return <tr key={meta.name}><th scope="row">{meta.label}</th><td data-tone={result.tone}>{result.label}</td><td>{service?.regionCode || "—"}</td></tr>;
      })}</tbody></table>
    </TabsContent>)}
    <p className="gl-secondary">仅“已解锁”计入数量；部分可用、未知和检测失败单独显示。结果来自节点出口检测，不代表客户端整条线路已验证。</p>
  </Tabs>;
}

export function IPQuality({ control, names }: { control: QualityControl; names: Map<string, string> }) {
  const [query, setQuery] = useState("");
  const { results, error, reload } = control;
  const records = control.records.filter(record => `${names.get(record.nodeId) ?? record.nodeId} ${record.address}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
  return <section className="gl-settings-section gl-quality" aria-label="IP 质量与解锁评测">
    <header className="gl-quality-heading"><div><h2>节点质量列表</h2><p className="gl-secondary">按实际出口查看评分与解锁结果，展开可查看分类详情。</p></div><Button variant="outline" onClick={reload}>刷新结果</Button></header>
    <div className="gl-toolbar"><label className="gl-search"><Search aria-hidden="true"/><input aria-label="搜索质量记录" placeholder="搜索节点或出口 IP…" value={query} onChange={event => setQuery(event.target.value)}/></label></div>
    {error ? <p role="alert">{error}</p> : null}
    {!results ? <p role="status">{error ? "未能读取评测记录，请刷新重试。" : "正在读取评测记录…"}</p> : !records.length ? <p className="gl-secondary">{query ? "没有匹配的出口记录，可清除筛选查看其他节点。" : "暂无出口记录和检测结果。"}</p> : null}
    <div className="gl-quality-list">{records.map(record => {
      const { check, nodeId, address } = record;
      return <article key={`${nodeId}/${address}`} className="gl-quality-card">
        <details><summary className="gl-quality-row">
          <span className="gl-quality-identity"><strong>{names.get(nodeId) ?? nodeId}</strong><span className="gl-secondary">{address} · {address.includes(":") ? "IPv6" : "IPv4"}</span></span>
          <AssessmentBadge language="zh-CN" assessment={check?.assessment}/><UnlockSummary record={record}/>
          <span className="gl-secondary gl-quality-time">{check?.checkedAt ? <time dateTime={check.checkedAt}>{new Date(check.checkedAt).toLocaleString()}</time> : "尚未检测"}</span>
          <span className="gl-secondary">展开详情</span>
        </summary>
        <QualityRecordDetails record={record} control={control}/>
        </details>
      </article>;
    })}</div>
  </section>;
}

export function QualityRecordDetails({ record, control }: { record: QualityRecord; control: QualityControl }) {
  const { target, check } = record;
  const { busy, startCheck } = control;
  const running = check?.state === "pending" || check?.state === "running";
  const history = qualityHistory(record);
  return (
        <div className="gl-quality-detail">
          <div className="gl-quality-heading"><p className="gl-secondary">{check ? qualityStates[check.state] : "尚未检测"}{!target ? " · 未绑定当前节点，保留历史报告" : !target.available ? " · 节点离线或诊断程序尚未就绪" : ""}</p><Button variant="outline" disabled={busy || running || !target?.available} onClick={() => target && void startCheck(target)}>{running ? qualityStates[check!.state] : check?.report ? "重新检测" : "检测"}</Button></div>
          {history ? <p className="gl-quality-history" role="note">历史检测结果，不能代表当前解锁状态。{check?.assessment.status === "expired" ? "检测已过期，建议复测。" : ""}</p> : null}
          {check?.error ? <p role="status">{errors[check.error] ?? "检测未完成"}；已有报告保留。</p> : null}
          {check?.report ? <>
            <AssessmentSummary language="zh-CN" assessment={check.assessment} report={check.report} checkedAt={check.checkedAt}/>
            <p>{[check.report.organization, check.report.asn, check.report.regionName, check.report.city].filter(Boolean).join(" · ")}</p>
            <UnlockDetails record={record}/>
            <details><summary>来源证据与 IP 风险</summary><p className="gl-secondary">来源原分保留各自量纲，不把缺失值当成零风险。</p><dl>{check.report.scores.map(score => <div key={score.source}><dt>{score.source}</dt><dd>{score.value}</dd></div>)}</dl><p>IPPure：{check.report.ippure?.status === "ok" ? check.report.ippure.riskScore : check.report.ippure?.status ?? "未取得结果"}</p><p>{check.report.riskFactors?.map(factor => `${factor.source} ${factor.kind}: ${factor.value ? "是" : "否"}`).join(" · ")}</p></details>
          </> : <p className="gl-secondary">未取得有效报告，不推测解锁状态或评分。</p>}
        </div>
  );
}
