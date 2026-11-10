import { hostNames } from "./control-format";
import { useEffect, useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectControl } from "@/components/SelectControl";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { LatencyCell, latencyKey, type RouteLatency } from "./RouteLatency";
import type { Inventory, Plan } from "./control-types";
const unlimited: Plan = { totalBytes: "0", expiryTime: "0", resetDays: 0, enabled: true };
export function AvailabilityEditor({ inventory, disabled, save, initialNodeID = "", expanded = false }: { expanded?: boolean; initialNodeID?: string; inventory: Inventory; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean> }) {
  const formID = useId();
  const names = hostNames(inventory);
  const [id, setID] = useState(initialNodeID);
  const [reason, setReason] = useState("traffic-exhausted");
  const [resumeAt, setResumeAt] = useState("");
  const [error, setError] = useState("");
  const entries = new Map(inventory.endpoints.filter(e => !e.retired).map(e => [e.entryId, names.get(e.entryId) ?? e.entryId]));
  for (const n of inventory.runtimes) if (!entries.has(n.id)) entries.set(n.id, names.get(n.id) ?? n.id);
  if (inventory.state === "empty") for (const n of inventory.nodes) if (!entries.has(n.id)) entries.set(n.id, n.name);
  const state = inventory.availability;
  const pause = state?.nodes[id];
  const reset = inventory.endpoints.find(e => e.entryId === id)?.nextResetAt;
  const localTime = (value: string) => { const date = new Date(value); return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  return <details open={expanded} className="gl-form-disclosure"><summary className="cursor-pointer">临时停用与恢复验证</summary><p className="my-3 text-sm text-muted-foreground">保留配置、身份、授权和账本，仅暂停订阅发布及本次线路验收。到期只开始重新验证，不直接认定恢复；已缓存的客户端订阅需要刷新。</p><form onSubmit={event => {
    event.preventDefault(); setError("");
    const date = resumeAt ? new Date(resumeAt) : undefined;
    if (date && (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now())) { setError("请选择未来的恢复时间。"); return; }
    if (id && state) void save("availability", { id, reason, resumeAt: date?.toISOString(), expectedRevision: state.revision });
  }}><FieldGroup>
    <Field><FieldLabel htmlFor={`${formID}-availability-node`}>节点</FieldLabel><SelectControl id={`${formID}-availability-node`} aria-label="节点" required disabled={disabled} value={id} onValueChange={value => { setID(value); setResumeAt(""); setError(""); }} placeholder="请选择" options={[...entries].map(([value, label]) => ({ value, label }))} /></Field>
    <Field><FieldLabel htmlFor={`${formID}-availability-reason`}>原因</FieldLabel><SelectControl id={`${formID}-availability-reason`} aria-label="原因" disabled={disabled} value={reason} onValueChange={setReason} options={[{ value: "traffic-exhausted", label: "流量用尽" }, { value: "maintenance", label: "维护" }]} /></Field>
    <Field data-invalid={!!error}><FieldLabel>恢复验证时间（本机时区；留空则手动恢复）<Input type="datetime-local" disabled={disabled} aria-invalid={!!error} value={resumeAt} onChange={event => setResumeAt(event.target.value)} /></FieldLabel>{error ? <p role="alert">{error}</p> : null}</Field>
    {reset && Date.parse(reset) > Date.now() ? <Button type="button" variant="outline" disabled={disabled} onClick={() => setResumeAt(localTime(reset))}>使用下次流量重置时间</Button> : null}
    {pause ? <p role="status">{pause.reason === "traffic-exhausted" ? "流量用尽" : "维护"} · {pause.resumeAt && !pause.resumeAt.startsWith("0001-") ? `恢复验证时间 ${new Date(pause.resumeAt).toLocaleString()}；是否可用以最新线路验证为准` : "等待手动恢复"}</p> : null}
    <div className="flex flex-wrap gap-2"><Button type="submit" disabled={disabled || !id || !state}>保存临时停用</Button>{pause ? <Button type="button" variant="outline" disabled={disabled} onClick={() => void save("availability", { id, reason: "resume", expectedRevision: state?.revision })}>立即重新验证</Button> : null}</div>
  </FieldGroup></form></details>;
}

export function PlanEditor({ initial, disabled, onSave, onDirtyChange }: { initial: Plan; disabled: boolean; onSave: (plan: Plan) => Promise<boolean>; onDirtyChange?: (dirty:boolean)=>void }) {
 const [plan,setPlan]=useState(initial);
 const unit=1073741824n;
 const [quota,setQuota]=useState(()=>{const n=BigInt(initial.totalBytes);return n===0n?"0":`${n/unit}.${((n%unit)*1000n/unit).toString().padStart(3,"0")}`.replace(/\.?0+$/,"");});
 const [error,setError]=useState("");
 const dateValue=(value:string)=>{if(value==="0")return "";const d=new Date(Number(value));if(!Number.isFinite(d.getTime()))return "";return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);};
 const [date,setDate]=useState(()=>dateValue(initial.expiryTime));
 return <form onSubmit={async event=>{event.preventDefault();if(!error&&await onSave(plan))onDirtyChange?.(false);}}><FieldGroup>
  <Field><FieldLabel>总额度（GiB，0 不限）<Input required inputMode="decimal" pattern="[0-9]+([.][0-9]{1,9})?" disabled={disabled} value={quota} onChange={event=>{onDirtyChange?.(true);const value=event.target.value;setQuota(value);if(!/^[0-9]+(?:\.[0-9]{1,9})?$/.test(value)){setError("请输入有效的额度，最多 9 位小数。");return;}const [whole,fraction=""]=value.split(".");const bytes=BigInt(whole)*unit+BigInt(fraction||"0")*unit/10n**BigInt(fraction.length);if(bytes>18446744073709551615n){setError("额度超出支持范围。");return;}setError("");setPlan({...plan,totalBytes:String(bytes)});}}/></FieldLabel></Field>
  <Field><FieldLabel>到期时间<Input type="datetime-local" disabled={disabled||plan.expiryTime==="0"} required={plan.expiryTime!=="0"} value={date} onChange={e=>{onDirtyChange?.(true);setDate(e.target.value);const value=new Date(e.target.value).getTime();if(Number.isFinite(value))setPlan({...plan,expiryTime:String(value)});}}/></FieldLabel><label className="gl-checkbox"><input type="checkbox" disabled={disabled} checked={plan.expiryTime==="0"} onChange={e=>{onDirtyChange?.(true);if(e.target.checked)setPlan({...plan,expiryTime:"0"});else {const value=Date.now()+30*86400000;setDate(dateValue(String(value)));setPlan({...plan,expiryTime:String(value)});}}}/>不限到期时间</label></Field>
  <Field><FieldLabel>周期天数（0 不重置）<Input type="number" min={0} max={3650} required disabled={disabled} value={plan.resetDays} onChange={event=>{onDirtyChange?.(true);setPlan({...plan,resetDays:Number(event.target.value)});}}/></FieldLabel></Field>
  <Field><FieldLabel className="gl-toggle-label">启用账户<input className="gl-toggle" type="checkbox" role="switch" disabled={disabled} checked={plan.enabled} onChange={event=>{onDirtyChange?.(true);setPlan({...plan,enabled:event.target.checked});}}/></FieldLabel></Field>
  {error?<p role="alert" className="text-destructive">{error}</p>:null}<Button className="gl-wide" type="submit" disabled={disabled||!!error}>保存账户配置</Button>
 </FieldGroup></form>;
}

export function CreateAccount({ inventory, disabled, save }: { inventory: Inventory; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean> }) {
  const id = useRef(crypto.randomUUID());
  const names = hostNames(inventory);
  const [name, setName] = useState("");
  const [entries, setEntries] = useState<string[]>([]);
  useEffect(() => {
    if (inventory.accounts.some(item => item.account.id === id.current)) {
      id.current = crypto.randomUUID();
      setName("");
      setEntries([]);
    }
  }, [inventory.accounts]);
  return <details open className="gl-form-disclosure"><summary className="cursor-pointer">新增账户</summary><form className="mt-3" onSubmit={event => { event.preventDefault(); if (entries.length && name.trim()) void save("accounts", { id: id.current, name: name.trim(), entryIds: entries, plan: unlimited }); }}><FieldGroup><Field><FieldLabel>名称<Input required value={name} disabled={disabled} onChange={event => setName(event.target.value)} /></FieldLabel></Field>{inventory.endpoints.filter(e => !e.retired).map(endpoint => <Field key={endpoint.id}><FieldLabel><input type="checkbox" disabled={disabled} checked={entries.includes(endpoint.entryId)} onChange={event => setEntries(event.target.checked ? [...entries, endpoint.entryId] : entries.filter(id => id !== endpoint.entryId))} />{names.get(endpoint.entryId) ?? endpoint.entryId}</FieldLabel></Field>)}<Button type="submit" disabled={disabled || entries.length === 0}>创建（默认不限额，随后编辑）</Button></FieldGroup></form></details>;
}

export function CreateRoute({ inventory, disabled, save, latencies, now, latencyFailed }: { inventory: Inventory; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean>; latencies: Map<string, RouteLatency>; now: number; latencyFailed: boolean }) {
  const formID = useId();
  const names = hostNames(inventory);
  const [mode, setMode] = useState("server");
  const [transport, setTransport] = useState("ipv4-ss2022");
  const [sourceIpv6, setSourceIpv6] = useState("");
  const [serverIpv6, setServerIpv6] = useState("");
  const [relayID, setRelayID] = useState("none");
  const [relayIpv6, setRelayIpv6] = useState("");
  const [name, setName] = useState("");
  const id = useRef(crypto.randomUUID());
  const [accountID, setAccountID] = useState("");
  const [entryID, setEntryID] = useState("");
  const [egressID, setEgressID] = useState("");
  useEffect(() => {
    if (inventory.routes.some(item => item.id === id.current) || inventory.clientChains?.some(item => item.id === id.current)) {
      id.current = crypto.randomUUID();
      setAccountID(""); setEntryID(""); setEgressID(""); setName("");
      setSourceIpv6(""); setServerIpv6("");
      setRelayID("none"); setRelayIpv6("");
    }
  }, [inventory.routes, inventory.clientChains]);
  const account = inventory.accounts.find(a => a.account.id === accountID);
  const entry = inventory.runtimes.find(node => node.role === "entry" && node.id === entryID);
  const ipv6Chain = mode === "client" && transport === "ipv6-ss2022";
  const relayEnabled = ipv6Chain && relayID !== "none";
  const landings = ipv6Chain ? inventory.runtimes.filter(n => n.role === "landing").map(n => n.id) : entry?.peers ?? [];
  return <form onSubmit={event => {
    event.preventDefault();
    if (!account || !entry || !landings.includes(egressID) || ipv6Chain && (!sourceIpv6.trim() || !serverIpv6.trim()) || relayEnabled && (!relayIpv6.trim() || !landings.includes(relayID) || relayID === egressID || relayID === entryID)) return;
    void save(mode === "client" ? "client-chains" : "routes", { id: id.current, accountId: accountID, entryId: entryID, egressId: egressID, enabled: true, ...(mode === "client" ? { name: name.trim(), transport, ...(ipv6Chain ? { sourceIpv6: relayEnabled ? relayIpv6.trim() : sourceIpv6.trim(), serverIpv6: serverIpv6.trim(), ...(relayEnabled ? { relayId: relayID, relaySourceIpv6: sourceIpv6.trim(), relayServerIpv6: relayIpv6.trim() } : {}) } : {}) } : { hideNative: false }), expectedRevision: account.account.desiredRevision });
  }}><FieldGroup>
    <Field><FieldLabel htmlFor={`${formID}-mode`}>生成模式</FieldLabel><SelectControl id={`${formID}-mode`} aria-label="生成模式" disabled={disabled} value={mode} onValueChange={value => { setMode(value); setEgressID(""); }} options={[{ value: "server", label: "转发" }, { value: "client", label: "链式" }]} /></Field>
    {mode === "client" ? <>
      <p className="text-sm text-muted-foreground">仅 TCP；使用独立落地凭据。仅 Mihomo 格式包含链式配置，普通链接订阅不包含；现有服务端转发保持不变。停用后请更新客户端订阅。</p>
      <Field><FieldLabel>组合名称<Input required maxLength={64} disabled={disabled} value={name} onChange={event => setName(event.target.value)} placeholder="香港 → 落地" /></FieldLabel></Field>
      <Field><FieldLabel htmlFor={`${formID}-transport`}>落地传输</FieldLabel><SelectControl id={`${formID}-transport`} aria-label="落地传输" disabled={disabled} value={transport} onValueChange={value => { setTransport(value); setEgressID(""); }} options={[{ value: "ipv4-ss2022", label: "公网 IPv4 · SS2022" }, { value: "ipv6-ss2022", label: "公网 IPv6 · SS2022" }]} /></Field>
    </> : null}
    <Field><FieldLabel htmlFor={`${formID}-account`}>账户</FieldLabel><SelectControl id={`${formID}-account`} aria-label="账户" required disabled={disabled} value={accountID} onValueChange={setAccountID} placeholder="请选择" options={inventory.accounts.map(a => ({ value: a.account.id, label: a.account.displayName }))} /></Field>
    <Field><FieldLabel htmlFor={`${formID}-entry`}>入口</FieldLabel><SelectControl id={`${formID}-entry`} aria-label="入口" required disabled={disabled} value={entryID} onValueChange={value => { setEntryID(value); setEgressID(""); }} placeholder="请选择" options={inventory.runtimes.filter(n => n.role === "entry").map(n => ({ value: n.id, label: names.get(n.id) ?? n.id }))} /></Field>
    {ipv6Chain ? <Field><FieldLabel htmlFor={`${formID}-relay`}>中转节点</FieldLabel><SelectControl id={`${formID}-relay`} aria-label="中转节点" disabled={disabled} value={relayID} onValueChange={setRelayID} options={[{value:"none",label:"无（双跳）"},...landings.filter(id=>id!==entryID).map(id=>({value:id,label:names.get(id)??id,disabled:id===egressID}))]} /></Field> : null}
    <Field><FieldLabel htmlFor={`${formID}-landing`}>{ipv6Chain ? "落地" : "已授权落地"}</FieldLabel><SelectControl id={`${formID}-landing`} aria-label={ipv6Chain ? "落地" : "已授权落地"} required disabled={disabled} value={egressID} onValueChange={setEgressID} placeholder="请选择" options={landings.map(id => ({ value: id, label: `${names.get(id) ?? id}${!ipv6Chain ? optionLatency(latencies.get(latencyKey(entryID, id)), now, latencyFailed) : ""}` }))} /></Field>
    {ipv6Chain ? <><p className="text-sm text-muted-foreground">使用已核验的公网 IPv6 单一地址；每一跳只允许上一跳地址连接，地址变化后需重新授权。</p><Field><FieldLabel>入口出口 IPv6<Input required disabled={disabled} value={sourceIpv6} onChange={event => setSourceIpv6(event.target.value)} /></FieldLabel></Field>{relayEnabled ? <Field><FieldLabel>中转监听及出口 IPv6<Input required disabled={disabled} value={relayIpv6} onChange={event => setRelayIpv6(event.target.value)} /></FieldLabel></Field> : null}<Field><FieldLabel>落地监听 IPv6<Input required disabled={disabled} value={serverIpv6} onChange={event => setServerIpv6(event.target.value)} /></FieldLabel></Field></> : null}
    {!ipv6Chain && entryID && egressID ? <div className="text-sm"><span className="text-muted-foreground">落地传输端口 TCP 1080 参考延迟：</span><LatencyCell value={latencies.get(latencyKey(entryID, egressID))} now={now} failed={latencyFailed} /></div> : null}
    <Button type="submit" disabled={disabled || !account || !entry || !egressID || mode === "client" && !name.trim() || ipv6Chain && (!sourceIpv6.trim() || !serverIpv6.trim()) || relayEnabled && (!relayIpv6.trim() || relayID === egressID || relayID === entryID)}>新增线路</Button>
  </FieldGroup></form>;
}

function optionLatency(value: RouteLatency | undefined, now: number, failed: boolean) {
  if (!value) return " · 未检测";
  if (failed || value.state === "stale" || value.checkedAt && now - Date.parse(value.checkedAt) > 120_000) return " · 已过期";
  if (value.state === "ready" && value.latencyMs != null) return ` · ${value.latencyMs.toFixed(1)} ms${value.latencyMs > 100 ? "（偏高）" : ""}`;
  return value.state === "unreachable" ? " · 不可达" : value.state === "unavailable" ? " · 节点离线或暂停" : value.state === "pending" ? " · 检测中" : " · 未检测";
}
