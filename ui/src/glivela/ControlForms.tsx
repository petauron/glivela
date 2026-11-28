import { useEffect, useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectControl } from "@/components/SelectControl";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { LatencyCell, latencyKey, type RouteLatency } from "./RouteLatency";
import type { Inventory, Plan } from "./control-types";
const unlimited: Plan = { totalBytes: "0", expiryTime: "0", resetDays: 0, enabled: true };
export function AvailabilityEditor({ inventory, names, disabled, save, initialNodeID = "", expanded = false }: { expanded?: boolean; initialNodeID?: string; inventory: Inventory; names: Map<string, string>; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean> }) {
  const formID = useId();
  const [id, setID] = useState(initialNodeID);
  const [reason, setReason] = useState("traffic-exhausted");
  const [resumeAt, setResumeAt] = useState("");
  const [error, setError] = useState("");
  const entries = new Map(inventory.endpoints.filter(e => !e.retired).map(e => [e.entryId, names.get(e.entryId) ?? e.entryId]));
  for (const n of inventory.runtimes) if (!entries.has(n.id)) entries.set(n.id, names.get(n.id) ?? n.id);
  if (inventory.state === "empty") for (const n of inventory.nodes) if (!entries.has(n.id)) entries.set(n.id, names.get(n.id) ?? n.name);
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

export function CreateAccount({ inventory, names, disabled, save }: { inventory: Inventory; names: Map<string, string>; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean> }) {
  const id = useRef(crypto.randomUUID());
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

export function CreateRoute({ inventory, names, disabled, save, latencies, now, latencyFailed }: { inventory: Inventory; names: Map<string, string>; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean>; latencies: Map<string, RouteLatency>; now: number; latencyFailed: boolean }) {
  const formID = useId();
  const id = useRef(crypto.randomUUID());
  const [mode, setMode] = useState<"two-hop" | "pooled">("two-hop");
  const [accountID, setAccountID] = useState("");
  const [entryID, setEntryID] = useState("");
  const [relayPoolID, setRelayPoolID] = useState("");
  const [egressID, setEgressID] = useState("");
  const [landingAddress, setLandingAddress] = useState("");
  const [expectedExit, setExpectedExit] = useState("");
  const [egressIp, setEgressIp] = useState("");
  const [ingressFamily, setIngressFamily] = useState("auto");
  const [routeName, setRouteName] = useState("");
  const [udp, setUdp] = useState(false);
  const [hideNative, setHideNative] = useState(false);
  useEffect(() => {
    if (inventory.routes.some(item => item.id === id.current)) {
      id.current = crypto.randomUUID();
      setAccountID(""); setEntryID(""); setRelayPoolID(""); setEgressID("");
      setLandingAddress(""); setExpectedExit(""); setEgressIp(""); setIngressFamily("auto"); setRouteName("");
      setUdp(false); setHideNative(false);
    }
  }, [inventory.routes]);
  const account = inventory.accounts.find(a => a.account.id === accountID);
  const entry = inventory.runtimes.find(node => node.role === "entry" && node.id === entryID);
  const pools = inventory.relayPools ?? [];
  const selectedPool = pools.find(pool => pool.id === relayPoolID);
  const twoHopLandings = entry?.peers ?? [];
  const pooledLandings = inventory.runtimes.filter(node => node.role === "landing" && node.id !== entryID);
  const selectedLandingRuntime = pooledLandings.find(node => node.id === egressID);
  const entryCapableForPool = !!entry?.relayPoolCapable;
  const canSubmit = mode === "two-hop"
    ? !!account && !!entry && twoHopLandings.includes(egressID)
    : !!account && !!entry && entryCapableForPool && !!selectedPool && !!selectedLandingRuntime;
  return <form onSubmit={event => {
    event.preventDefault();
    if (!canSubmit || !account || !entry) return;
    if (mode === "pooled") {
      const payload: Record<string, unknown> = {
        id: id.current,
        accountId: accountID,
        entryId: entryID,
        egressId: egressID,
        relayPoolId: relayPoolID,
        enabled: true,
        hideNative,
        expectedRevision: account.account.desiredRevision,
      };
      if (udp) payload.udp = true;
      if (landingAddress.trim()) payload.landingAddress = landingAddress.trim();
      if (expectedExit.trim()) payload.expectedExit = expectedExit.trim();
      if (egressIp.trim()) payload.egressIp = egressIp.trim();
      if (ingressFamily !== "auto") payload.ingressFamily = ingressFamily;
      if (routeName.trim()) payload.name = routeName.trim();
      void save("routes", payload);
      return;
    }
    const payload: Record<string, unknown> = {
      id: id.current,
      accountId: accountID,
      entryId: entryID,
      egressId: egressID,
      enabled: true,
      hideNative,
      expectedRevision: account.account.desiredRevision,
    };
    if (udp) payload.udp = true;
    void save("routes", payload);
  }}><FieldGroup>
    <div className="gl-segment" role="group" aria-label="线路类型">
      <button type="button" aria-pressed={mode === "two-hop"} onClick={() => { setMode("two-hop"); setEgressID(""); }}>两跳固定落地</button>
      <button type="button" aria-pressed={mode === "pooled"} onClick={() => { setMode("pooled"); setEgressID(""); }}>三跳中转池</button>
    </div>
    <Field><FieldLabel htmlFor={`${formID}-account`}>账户</FieldLabel><SelectControl id={`${formID}-account`} aria-label="账户" required disabled={disabled} value={accountID} onValueChange={setAccountID} placeholder="请选择" options={inventory.accounts.map(a => ({ value: a.account.id, label: a.account.displayName }))} /></Field>
    <Field><FieldLabel htmlFor={`${formID}-entry`}>入口</FieldLabel><SelectControl id={`${formID}-entry`} aria-label="入口" required disabled={disabled} value={entryID} onValueChange={value => { setEntryID(value); setEgressID(""); }} placeholder="请选择" options={inventory.runtimes.filter(n => n.role === "entry").map(n => ({ value: n.id, label: `${names.get(n.id) ?? n.id}${mode === "pooled" && !n.relayPoolCapable ? "（尚未上报中转池能力）" : ""}` }))} /></Field>
    {mode === "pooled" ? <>
      <Field>
        <FieldLabel htmlFor={`${formID}-pool`}>中转池</FieldLabel>
        <SelectControl id={`${formID}-pool`} aria-label="中转池" required disabled={disabled || pools.length === 0} value={relayPoolID} onValueChange={setRelayPoolID} placeholder={pools.length ? "请选择中转池" : "请先在「中转池与拓扑」创建中转池"} options={pools.map(pool => ({ value: pool.id, label: `${pool.name}（${pool.members.filter(m => !m.drained && !m.nodeSuspended && m.runtimeReady).length}/${pool.members.length} 就绪 · expected=${pool.strategy.expected}）` }))} />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${formID}-pooled-landing`}>固定出口落地</FieldLabel>
        <SelectControl id={`${formID}-pooled-landing`} aria-label="固定出口落地" required disabled={disabled || !entryID} value={egressID} onValueChange={value => {
          setEgressID(value);
          // Leave landingAddress and expectedExit empty by default so backend
          // ChangeRoute applies its authoritative IPv6Only / Transport default.
          setLandingAddress("");
          setExpectedExit("");
        }} placeholder="请选择已登记落地" options={pooledLandings.map(node => ({ value: node.id, label: `${names.get(node.id) ?? node.id}${node.egressIp ? ` · 出口 ${node.egressIp}` : ""}${node.occupiedPort24000?.length ? " · 24000 待切窗" : ""}` }))} />
      </Field>
      <Field><FieldLabel htmlFor={`${formID}-route-name`}>线路备注名（可选）<Input id={`${formID}-route-name`} disabled={disabled} placeholder="例如：日本固定出口（池化）" value={routeName} onChange={event => setRouteName(event.target.value)} /></FieldLabel></Field>
      <Field>
        <FieldLabel htmlFor={`${formID}-landing-address`}>
          落地连接地址（留空使用后端默认地址）
          <Input id={`${formID}-landing-address`} disabled={disabled} placeholder="留空交给控制面按落地默认传输地址选择" value={landingAddress} onChange={event => setLandingAddress(event.target.value)} />
        </FieldLabel>
        {selectedLandingRuntime && (selectedLandingRuntime.publicIpv4 || selectedLandingRuntime.publicIpv6) ? (
          <div className="gl-address-hints" role="group" aria-label="落地公网候选地址">
            <Button type="button" variant="outline" disabled={disabled || landingAddress === ""} onClick={() => setLandingAddress("")}>使用后端默认</Button>
            {selectedLandingRuntime.publicIpv4 ? (
              <Button type="button" variant="outline" disabled={disabled} onClick={() => setLandingAddress(selectedLandingRuntime.publicIpv4!)}>指定 IPv4：{selectedLandingRuntime.publicIpv4}</Button>
            ) : null}
            {selectedLandingRuntime.publicIpv6 ? (
              <Button type="button" variant="outline" disabled={disabled} onClick={() => setLandingAddress(selectedLandingRuntime.publicIpv6!)}>指定 IPv6：{selectedLandingRuntime.publicIpv6}</Button>
            ) : null}
          </div>
        ) : null}
        <FieldDescription>双栈落地默认留空时由控制面选择默认传输地址；若中转池仅配置 IPv4 出站，请勿强制指定 IPv6 地址。</FieldDescription>
      </Field>
      <div className="gl-pool-member-ip-grid">
        <Field><FieldLabel htmlFor={`${formID}-egress-ip`}>指定出口源 IP（可选）<Input id={`${formID}-egress-ip`} disabled={disabled} placeholder="留空沿用落地默认出口" value={egressIp} onChange={event => setEgressIp(event.target.value)} /></FieldLabel></Field>
        <Field><FieldLabel htmlFor={`${formID}-expected-exit`}>期望出口 IP（可选）<Input id={`${formID}-expected-exit`} disabled={disabled} placeholder={selectedLandingRuntime?.egressIp ? `默认：${selectedLandingRuntime.egressIp}` : "留空沿用落地默认出口"} value={expectedExit} onChange={event => setExpectedExit(event.target.value)} /></FieldLabel></Field>
      </div>
      <Field><FieldLabel htmlFor={`${formID}-ingress-family`}>入口到中转地址族</FieldLabel><SelectControl id={`${formID}-ingress-family`} aria-label="入口到中转地址族" disabled={disabled} value={ingressFamily} onValueChange={setIngressFamily} options={[{ value: "auto", label: "自动（优先兼容的 IPv6 / IPv4）" }, { value: "ipv4", label: "仅 IPv4" }, { value: "ipv6", label: "仅 IPv6" }]} /></Field>
      {entry && !entryCapableForPool ? <p role="alert" className="gl-inline-error">该入口尚未上报中转池渲染能力，暂不可提交三跳池化线路；请先升级入口并确认回执能力。</p> : null}
    </> : <>
      <Field><FieldLabel htmlFor={`${formID}-landing`}>已授权落地</FieldLabel><SelectControl id={`${formID}-landing`} aria-label="已授权落地" required disabled={disabled} value={egressID} onValueChange={setEgressID} placeholder="请选择" options={twoHopLandings.map(id => ({ value: id, label: `${names.get(id) ?? id}${optionLatency(latencies.get(latencyKey(entryID, id)), now, latencyFailed)}` }))} /></Field>
      {entryID && egressID ? <div className="text-sm"><span className="text-muted-foreground">落地传输端口 TCP 1080 参考延迟：</span><LatencyCell value={latencies.get(latencyKey(entryID, egressID))} now={now} failed={latencyFailed} /></div> : null}
    </>}
    <Field><FieldLabel className="gl-toggle-label" htmlFor={`${formID}-udp`}>启用 UDP（XUDP）<input id={`${formID}-udp`} className="gl-toggle" type="checkbox" role="switch" disabled={disabled} checked={udp} onChange={event => setUdp(event.target.checked)} /></FieldLabel><FieldDescription>在既有 SS2022 TCP 隧道内承载 XUDP；UDP 443 保持阻断。</FieldDescription></Field>
    <Field><FieldLabel className="gl-toggle-label" htmlFor={`${formID}-hide-native`}>隐藏入口直连<input id={`${formID}-hide-native`} className="gl-toggle" type="checkbox" role="switch" aria-describedby={`${formID}-hide-native-hint`} disabled={disabled} checked={hideNative} onChange={event => setHideNative(event.target.checked)} /></FieldLabel><FieldDescription id={`${formID}-hide-native-hint`}>在订阅中隐藏该入口的 VLESS 直连节点，仅保留转发线路；保留原身份与历史流量。</FieldDescription></Field>
    <Button type="submit" disabled={disabled || !canSubmit}>{mode === "pooled" ? "新增三跳池化线路" : "新增线路"}</Button>
  </FieldGroup></form>;
}

function optionLatency(value: RouteLatency | undefined, now: number, failed: boolean) {
  if (!value) return " · 未检测";
  if (failed || value.state === "stale" || value.checkedAt && now - Date.parse(value.checkedAt) > 120_000) return " · 已过期";
  if (value.state === "ready" && value.latencyMs != null) return ` · ${value.latencyMs.toFixed(1)} ms${value.latencyMs > 100 ? "（偏高）" : ""}`;
  return value.state === "unreachable" ? " · 不可达" : value.state === "unavailable" ? " · 节点离线或暂停" : value.state === "pending" ? " · 检测中" : " · 未检测";
}
