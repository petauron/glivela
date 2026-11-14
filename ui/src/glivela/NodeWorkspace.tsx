import { Fragment, useId, useState } from "react";
import { ChevronDown, ChevronRight, LockKeyhole, LockKeyholeOpen, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectControl } from "@/components/SelectControl";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AssessmentBadge } from "@/views/IPAssessment";
import { NetworkCell, type NetworkControl } from "./NetworkOptimization";
import { NodeEgress } from "./NodeEgress";
import { reported } from "./control-format";
import { QualityRecordDetails, UnlockSummary, type QualityControl } from "./IPQuality";
import { qualityHistory, qualityStates, serviceResult, unlockSummary, type QualityRecord } from "./quality-model";
import type { Inventory, Runtime } from "./control-types";

const columns = 5;
type Props = { onEgressSaved: () => Promise<void>; inventory: Inventory; names: Map<string, string>; agents?: {id:string; name:string}[]; onBind?: (nodeId:string, expectedAgentId:string, agentId:string)=>Promise<boolean>; quality: QualityControl; network: NetworkControl; disabled: boolean; onNetwork: (id: string) => void; onPause: (id: string) => void; onRetire: (id: string) => void; onRetireReturnedEntry?: (id: string, confirmation: string, confirmHostReturned: boolean) => Promise<boolean>; onRetireLanding?: (id: string, confirmation: string, confirmHostReturned: boolean) => Promise<boolean> };
type OverviewNode = { id: string; runtimes: Runtime[]; records: QualityRecord[] };
const rolesLabel = (nodes: Runtime[]) => nodes.length > 1 ? "线路＋落地" : nodes[0]?.role === "entry" ? "线路机" : "落地机";
const range = (values: number[]) => Math.min(...values) === Math.max(...values) ? String(Math.min(...values)) : `${Math.min(...values)}–${Math.max(...values)}`;

function qualitySummary(records: QualityRecord[]) {
  const current = records.filter(record => record.check?.report && !qualityHistory(record));
  const reports = current.length ? current : records.filter(record => record.check?.report);
  const scores = reports.flatMap(record => record.check?.assessment.score != null && record.check.assessment.status !== "ip_changed" ? [record.check.assessment.score] : []);
  return { reports, scores, history: !current.length && !!reports.length, current, total: records.filter(record => record.target).length };
}

export function NodeWorkspace(props: Props) {
  const { inventory, names, quality } = props;
  const [query, setQuery] = useState("");
  const [role, setRole] = useState("all");
  const [purpose, setPurpose] = useState("all");
  const [order, setOrder] = useState("quality");
  const search = query.trim().toLocaleLowerCase();
  const byHost = new Map<string, Runtime[]>();
  for (const node of inventory.runtimes) {
    const id = node.hostId || node.id;
    const runtimes = byHost.get(id) ?? [];
    runtimes.push(node); byHost.set(id, runtimes);
  }
  const rows: OverviewNode[] = [...byHost].map(([id, runtimes]) => {
    const ids = new Set(runtimes.map(node => node.id));
    const records = quality.records.filter(record => record.target ? ids.has(record.target.runtimeId) : record.nodeId === id);
    return { id, runtimes, records: records.sort((a, b) => Number(a.address.includes(":")) - Number(b.address.includes(":")) || a.address.localeCompare(b.address)) };
  });
  const nameFor = (node: OverviewNode) => names.get(node.id) ?? names.get(node.runtimes[0].id) ?? node.id;
  const ready = (node: Runtime) => node.runtimeReady && !inventory.availability?.nodes[node.id];
  const matching = rows.filter(node => {
    if (role !== "all" && !node.runtimes.some(runtime => runtime.role === role)) return false;
    if (search && !`${nameFor(node)} ${node.records.map(record => record.address).join(" ")}`.toLocaleLowerCase().includes(search)) return false;
    if (purpose === "all") return true;
    return node.records.some(record => {
      if (!record.target || !node.runtimes.some(runtime => runtime.id === record.target?.runtimeId && ready(runtime)) || !record.check?.report || qualityHistory(record)) return false;
      if (purpose === "residential") return record.check.assessment.ipType === "residential";
      const required = purpose === "streaming" ? ["Netflix", "DisneyPlus"] : ["ChatGPT"];
      return required.every(name => serviceResult(record.check?.report?.services.find(service => service.name === name)).unlocked);
    });
  }).sort((a, b) => {
    const available = (node: OverviewNode) => node.runtimes.every(ready);
    if (available(a) !== available(b)) return available(a) ? -1 : 1;
    if (order === "quality") {
      const score = (node: OverviewNode) => { const summary = qualitySummary(node.records); return !summary.history && summary.scores.length ? Math.min(...summary.scores) : -1; };
      const difference = score(b) - score(a);
      if (difference) return difference;
    }
    return nameFor(a).localeCompare(nameFor(b));
  });
  const reset = () => { setQuery(""); setRole("all"); setPurpose("all"); };
  return <div className="gl-primary gl-node-overview">
    <div className="gl-toolbar apps-three-xui-toolbar">
      <label className="gl-search"><Search aria-hidden="true"/><input aria-label="搜索节点" placeholder="搜索节点或出口 IP…" value={query} onChange={event => setQuery(event.target.value)}/></label>
      <SelectControl aria-label="节点角色" className="gl-overview-filter" value={role} onValueChange={setRole} options={[{ value: "all", label: "全部节点" }, { value: "entry", label: "线路机" }, { value: "landing", label: "落地机" }]}/>
      <SelectControl aria-label="按用途筛选" className="gl-overview-filter" value={purpose} onValueChange={setPurpose} options={[{ value: "all", label: "全部用途" }, { value: "ai", label: "ChatGPT" }, { value: "streaming", label: "Netflix + Disney+" }, { value: "residential", label: "家宽出口" }]}/>
      <SelectControl aria-label="节点排序" className="gl-overview-filter" value={order} onValueChange={setOrder} options={[{ value: "quality", label: "IP 质量优先" }, { value: "name", label: "按名称" }]}/>
      {query || role !== "all" || purpose !== "all" ? <Button variant="ghost" size="sm" onClick={reset}>清除筛选</Button> : null}
    </div>
    <div className="glivela-evidence-bar gl-secondary"><span>每个节点一行；展开查看 IPv4、IPv6 的具体结果。</span><span>多出口按各自结果显示范围，历史与未确认结果单独标记。</span></div>
    {quality.error ? <p role="alert" className="gl-overview-error">质量读取失败：{quality.error}<Button variant="ghost" onClick={quality.reload}>重试</Button></p> : null}
    <div className="glivela-node-list"><Table aria-label="Glivela 节点" className="glivela-comparison-table gl-node-summary-table">
      <colgroup><col className="glivela-node-column"/><col className="glivela-quality-column"/><col/><col className="glivela-state-column"/><col className="glivela-actions-column"/></colgroup>
      <TableHeader><TableRow><TableHead scope="col">节点</TableHead><TableHead scope="col" title="出口 IP 质量范围，不代表速度；质量排序采用当前出口最低评分。">IP 质量</TableHead><TableHead scope="col" title="每个出口分别计算已解锁服务数，不合并不同出口的成功结果。">解锁摘要</TableHead><TableHead scope="col">状态</TableHead><TableHead scope="col"><span className="sr-only">详情</span></TableHead></TableRow></TableHeader>
      <TableBody>{["entry", "landing"].map(group => {
        const groupRows = matching.filter(node => (role === "landing" || !node.runtimes.some(runtime => runtime.role === "entry") ? "landing" : "entry") === group);
        if (!groupRows.length) return null;
        return <Fragment key={group}><TableRow className="glivela-node-group"><TableCell colSpan={columns}>{group === "entry" ? "线路机" : "落地机"} · {groupRows.length} 个节点</TableCell></TableRow>{groupRows.map(node => <NodeRow key={node.id} {...props} node={node} name={nameFor(node)}/>)}</Fragment>;
      })}{!matching.length ? <TableRow><TableCell colSpan={columns} className="gl-overview-empty">没有匹配的节点<Button variant="ghost" onClick={reset}>清除筛选</Button></TableCell></TableRow> : null}</TableBody>
    </Table></div>
    <footer className="gl-list-footer">共 {rows.length} 个节点 · {inventory.runtimes.length} 个角色实例 · 当前显示 {matching.length} 个节点{!quality.results ? quality.error ? " · 质量记录读取失败" : " · 质量记录读取中…" : ""}</footer>
  </div>;
}

function NodeRow({ node, name, inventory, quality, agents = [], onBind, ...props }: Props & { node: OverviewNode; name: string }) {
  const [open, setOpen] = useState(false);
  const binding = inventory.nodes.find(item => item.id === node.id);
  const [selectedAgent, setSelectedAgent] = useState(binding?.centerAgentId ?? "");
  const detailId = useId();
  const summary = qualitySummary(node.records);
  const unlocks = summary.reports.map(record => unlockSummary(record.check?.report));
  const allUnlocked = unlocks.length > 0 && unlocks.every(result => result.count === result.total);
  const Icon = allUnlocked ? LockKeyholeOpen : LockKeyhole;
  const applied = node.runtimes.filter(runtime => runtime.runtimeReady && !inventory.availability?.nodes[runtime.id]).length;
  const paused = node.runtimes.filter(runtime => inventory.availability?.nodes[runtime.id]).length;
  const state = paused === node.runtimes.length ? "已停用" : applied === node.runtimes.length ? "已应用" : applied ? `${applied}/${node.runtimes.length} 已应用` : "待核验";
  const tone = paused === node.runtimes.length ? "muted" : applied === node.runtimes.length ? "good" : "warning";
  const toggle = () => setOpen(value => !value);
  return <>
    <TableRow data-node-id={node.id} data-state={open ? "selected" : undefined}>
      <TableCell><button type="button" className="gl-node-name" aria-label={`查看 ${name} 详情`} aria-expanded={open} aria-controls={detailId} onClick={toggle}><span><strong>{name}</strong><small>{rolesLabel(node.runtimes)} · {summary.total ? `${summary.total} 个当前出口` : "暂无当前出口记录"}</small></span></button></TableCell>
      <TableCell><button type="button" className="gl-overview-score" aria-label={`${name} · 查看 IP 评分说明`} aria-expanded={open} aria-controls={detailId} onClick={toggle}><span className="glivela-quality-score">{!quality.results ? <span className="gl-secondary">{quality.error ? "读取失败" : "读取中…"}</span> : summary.reports.length === 1 ? <AssessmentBadge language="zh-CN" assessment={summary.reports[0].check?.assessment}/> : <strong className="gl-overview-score-range">{summary.scores.length ? range(summary.scores) : "待检测"}</strong>}</span><span className="glivela-quality-meta gl-secondary">{summary.history ? `历史 · ${summary.reports.length} 份报告` : summary.total ? `${summary.scores.length}/${summary.total} 个出口已评分` : "暂无当前评分"}</span></button></TableCell>
      <TableCell><button type="button" className="gl-overview-score" aria-label={`${name} · 查看解锁详情`} aria-expanded={open} aria-controls={detailId} onClick={toggle}><span className="gl-unlock-summary" data-tone={!summary.history && summary.current.length === summary.total && allUnlocked ? "good" : "muted"}><Icon aria-hidden="true"/>{summary.history ? "历史 · " : ""}{unlocks.length ? `${range(unlocks.map(result => result.count))}/${unlocks[0].total} 已解锁` : "暂无确认结果"}</span><span className="glivela-quality-meta gl-secondary">{summary.history ? "当前结果待确认" : summary.total ? `${summary.current.length}/${summary.total} 个当前出口有报告` : "暂无当前报告"}</span></button></TableCell>
      <TableCell><span className="gl-status" data-tone={tone}>{state}</span>{node.runtimes.length > 1 ? <small className="gl-overview-reported gl-secondary">{node.runtimes.length} 个角色分别核验</small> : <small className="gl-overview-reported gl-secondary"><time dateTime={node.runtimes[0].reportedAt} title={node.runtimes[0].reportedAt}>{reported(node.runtimes[0].reportedAt)}</time></small>}</TableCell>
      <TableCell><button type="button" className="gl-icon-button" aria-label={`${open ? "收起" : "展开"} ${name} 详情`} aria-expanded={open} aria-controls={detailId} onClick={toggle}>{open ? <ChevronDown/> : <ChevronRight/>}</button></TableCell>
    </TableRow>
    {open ? <TableRow className="gl-overview-expanded"><TableCell colSpan={columns}><div id={detailId} className="gl-overview-detail" role="region" aria-label={`${name} 详情`}>
      <header><div><h2>{name}</h2><p className="gl-secondary">{rolesLabel(node.runtimes)}{node.runtimes.length > 1 ? " · 同机入口与落地分别显示应用状态" : ""}</p></div><Button variant="ghost" onClick={() => setOpen(false)}>收起详情</Button></header>
      {binding && agents.length > 0 && onBind ? <section className="gl-overview-runtime"><h3>关联 Vastora 主机</h3><p className="gl-secondary">选择实际对应的主机；关联后使用主机当前名称，仅影响面板显示。</p>{binding.centerAgentId && !agents.some(agent=>agent.id===binding.centerAgentId) ? <p role="status">已关联的主机不存在或不可见，请核对后重新选择。</p> : null}<SelectControl aria-label={`${name} 关联的 Vastora 主机`} value={selectedAgent || "unbound"} onValueChange={value => setSelectedAgent(value === "unbound" ? "" : value)} options={[{value:"unbound",label:"未关联"},...(selectedAgent && !agents.some(agent=>agent.id===selectedAgent)?[{value:selectedAgent,label:"已关联主机不可见",disabled:true}]:[]),...agents.map(agent=>({value:agent.id,label:agent.name}))]}/><Button variant="outline" disabled={props.disabled || selectedAgent === (binding.centerAgentId ?? "")} onClick={()=>void onBind(node.id,binding.centerAgentId ?? "",selectedAgent)}>保存关联</Button></section> : null}
      <section className="gl-overview-exits"><h3>出口质量与解锁</h3>{node.records.length ? node.records.map(record => <details key={`${record.nodeId}/${record.address}`} className="gl-overview-exit"><summary><span className="gl-quality-identity"><strong>{record.address.includes(":") ? "IPv6" : "IPv4"} · {record.address}</strong><span className="gl-secondary">{record.check ? qualityStates[record.check.state] ?? "待确认" : "尚未检测"}{record.check?.checkedAt ? ` · ${new Date(record.check.checkedAt).toLocaleString("zh-CN")}` : ""}</span></span><AssessmentBadge language="zh-CN" assessment={record.check?.assessment}/><UnlockSummary record={record}/></summary><QualityRecordDetails record={record} control={quality}/></details>) : <p className="gl-secondary">当前节点暂无可匹配的出口检测记录，不推测评分和解锁状态。</p>}</section>
      {node.runtimes.map(runtime => <RuntimeDetails key={runtime.id} node={runtime} inventory={inventory} {...props}/>)}
    </div></TableCell></TableRow> : null}
  </>;
}

function RuntimeDetails({ node, inventory, network, disabled, onNetwork, onPause, onRetire, onRetireLanding, onRetireReturnedEntry, onEgressSaved }: Pick<Props, "inventory" | "network" | "disabled" | "onNetwork" | "onPause" | "onRetire" | "onRetireLanding" | "onRetireReturnedEntry" | "onEgressSaved"> & { node: Runtime }) {
  const pause = inventory.availability?.nodes[node.id];
  const [confirmation, setConfirmation] = useState("");
  const [hostReturned, setHostReturned] = useState(false);
  const confirmationId = useId();
  const returnedId = useId();
  return <section className="gl-overview-runtime" data-runtime-id={node.id}><h3>{node.role === "entry" ? "线路端" : "落地端"} · <span className="gl-status" data-tone={pause ? "muted" : node.runtimeReady ? "good" : "warning"}>{pause ? "已停用" : node.runtimeReady ? "已应用" : "待核验"}</span></h3><p className="gl-secondary">配置修订 {node.revision} · 最后上报 {reported(node.reportedAt)}。应用回执不等于完整线路验证。</p><NetworkCell summary nodeId={node.id} control={network} onOpen={() => onNetwork(node.id)}/><div className="gl-overview-actions"><Button variant="outline" onClick={() => onNetwork(node.id)}>查看网络优化</Button><Button variant="outline" onClick={() => onPause(node.id)}>临时停用与恢复…</Button></div><details className="gl-context-details gl-identity"><summary>节点标识</summary><code>{node.id}</code></details>
    <NodeEgress node={node} disabled={disabled} onSaved={onEgressSaved}/>
    {node.role === "landing" && onRetireLanding && node.certificateId && pause?.reason === "maintenance" && (!pause.resumeAt || pause.resumeAt.startsWith("0001-")) ? <details className="gl-context-details"><summary>永久清退已退租落地…</summary><p>先停用全部关联线路，再清退。撤销运行身份、删除专属线路密钥和诊断记录，保留账号累计已用总额；其他节点的关联传输授权将撤销，不改变其余线路与账号账本。不会登录、停止或卸载退租主机。</p><label htmlFor={returnedId}><input id={returnedId} type="checkbox" checked={hostReturned} disabled={disabled} onChange={event => setHostReturned(event.target.checked)}/>确认该主机已退租，不再使用</label><label htmlFor={confirmationId}>输入节点标识 {node.id} 确认永久清退</label><Input id={confirmationId} value={confirmation} disabled={disabled} onChange={event => setConfirmation(event.target.value)} autoComplete="off" spellCheck={false}/><Button variant="outline" disabled={disabled || !hostReturned || confirmation !== node.id} onClick={() => void onRetireLanding(node.id, confirmation, hostReturned)}>永久清退落地</Button></details> : null}
    {node.role === "entry" && onRetireReturnedEntry && node.certificateId && pause?.reason === "maintenance" && (!pause.resumeAt || pause.resumeAt.startsWith("0001-")) ? <details className="gl-context-details"><summary>永久清退已退租入口…</summary><p>先停用关联线路。此操作不可撤销，将撤销入口身份并删除专属线路、密钥和检测记录，保留其他节点及账号累计用量。不会登录退租主机；迁移归档和备份仍需另行清理。</p><label htmlFor={returnedId}><input id={returnedId} type="checkbox" checked={hostReturned} disabled={disabled} onChange={event => setHostReturned(event.target.checked)}/>确认该主机已退租，不再使用</label><label htmlFor={confirmationId}>输入节点标识 {node.id} 确认永久清退</label><Input id={confirmationId} value={confirmation} disabled={disabled} onChange={event => setConfirmation(event.target.value)} autoComplete="off" spellCheck={false}/><Button variant="outline" disabled={disabled || !hostReturned || confirmation !== node.id} onClick={() => void onRetireReturnedEntry(node.id, confirmation, hostReturned)}>永久清退入口</Button></details> : null}
    {node.role === "entry" && pause?.reason === "maintenance" && (!pause.resumeAt || pause.resumeAt.startsWith("0001-")) ? <details className="gl-context-details"><summary>退役入口…</summary><p>将该离线入口及其线路移出当前列表和订阅，保留身份、配置、流量与历史。入口须至少 5 分钟未上报，且关联客户端链式监听已停用并应用；此操作不会停止或清理离线主机。</p><Button variant="outline" disabled={disabled} onClick={() => onRetire(node.id)}>确认退役</Button></details> : null}
  </section>;
}
