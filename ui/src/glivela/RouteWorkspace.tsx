import { useState } from "react";
import { Search, X, MoreHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SelectControl } from "@/components/SelectControl";
import { LatencyCell, latencyKey, type RouteLatency } from "./RouteLatency";
import { LinkSpeed, RouteSpeedSummary, speedKey, useLinkSpeed, type SpeedBody, type SpeedList } from "./LinkSpeed";
import { routeLabels } from "./control-format";
import type { Inventory } from "./control-types";
import { PathMTU } from "./PathMTU";

export function RouteWorkspace({inventory,names,disabled,save,latency,loadSpeeds,active}: {
 inventory:Inventory; names:Map<string,string>; disabled:boolean; save:(operation:string,body:unknown)=>Promise<boolean>;
 latency:{values:Map<string,RouteLatency>;now:number;busy:boolean;error:string;refresh:(force?:boolean)=>Promise<void>};
 loadSpeeds:(body:SpeedBody,signal?:AbortSignal)=>Promise<SpeedList>; active:boolean;
}) {
 const [query,setQuery]=useState("");const [filter,setFilter]=useState("all");const [modeFilter,setModeFilter]=useState("all");const [selected,setSelected]=useState("");const [deleteKey,setDeleteKey]=useState("");
 const speed = useLinkSpeed(loadSpeeds, active);
 const rows=[...inventory.routes.map(value=>({id:value.id,accountId:value.accountId,entryId:value.entryId,egressId:value.egressId,enabled:value.enabled,shared:false,port:1080,transport:"",sourceIpv6:"",serverIpv6:"",mode:"server",state:value.state,name:"",ipv4EgressId:value.ipv4EgressId,value})),...(inventory.clientChains??[]).map(value=>({id:value.id,accountId:value.accountId,entryId:value.entryId,egressId:value.egressId,enabled:value.enabled,shared:value.shared??false,port:value.port,transport:value.transport??"",sourceIpv6:value.sourceIpv6??"",serverIpv6:value.serverIpv6??"",mode:"client",state:value.enabled?"configured":"disabled",name:value.name,ipv4EgressId:undefined,value}))];
 const nodeName=(id:string)=>names.get(id)??id;
 const label=(row:typeof rows[number])=>row.name||`${nodeName(row.entryId)} → ${nodeName(row.egressId)}`;
 const accountName=(id:string)=>inventory.accounts.find(a=>a.account.id===id)?.account.displayName??id;
 const landingIds=(row:typeof rows[number])=>[...new Set([row.egressId,row.ipv4EgressId].filter((id):id is string=>!!id))];
 const routeLatency=(row:typeof rows[number],landingId:string)=>row.transport==="ipv6-ss2022"&&(!row.sourceIpv6||!row.serverIpv6)?undefined:latency.values.get(latencyKey(row.entryId,landingId,row.port,row.transport==="ipv6-ss2022"?row.sourceIpv6:"",row.transport==="ipv6-ss2022"?row.serverIpv6:""));
 const state=(row:typeof rows[number])=>row.mode==="client"&&row.enabled?"已配置 · 待客户端验证":routeLabels[row.state]??"未确认";
 const paused=(id:string)=>{
  const pause=inventory.availability?.nodes[id];
  if (!pause) return false;
  if (!pause.resumeAt || pause.resumeAt.startsWith("0001-")) return true;
  const resume=Date.parse(pause.resumeAt);
  return !Number.isFinite(resume) || resume>latency.now;
 };
 const listState=(row:typeof rows[number])=>{
  if (!row.enabled) return {enabled:false,detail:"线路开关已关闭。"};
  const account=inventory.accounts.find(item=>item.account.id===row.accountId);
  if (account && !account.account.plan.enabled) return {enabled:false,detail:"账户已停用，线路开关仍为启用。"};
  if (row.state==="policy-disabled") return {enabled:false,detail:"账户额度或策略限制了此线路，线路开关仍为启用。"};
  if (row.state==="temporarily-suspended" || landingIds(row).some(paused) || paused(row.entryId)) return {enabled:false,detail:"相关入口或落地暂时停用，线路开关仍为启用。"};
  return {enabled:true,detail:"线路已启用；实际连通性以检测结果为准。"};
 };
 const shown=rows.filter(row=>(filter==="all"||(filter==="enabled"?listState(row).enabled:!listState(row).enabled))&&(modeFilter==="all"||modeFilter===row.mode)&&`${label(row)} ${nodeName(row.entryId)} ${landingIds(row).map(nodeName).join(" ")} ${accountName(row.accountId)}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 const groups=new Map<string,typeof rows>();
 for(const row of shown) groups.set(row.entryId,[...(groups.get(row.entryId)??[]),row]);
 const rowKey=(row:typeof rows[number])=>`${row.mode}/${row.id}`;
 const itemKey=(row:typeof rows[number],landingId:string)=>`${rowKey(row)}/${landingId}`;
 const current=shown.find(row=>landingIds(row).some(landingId=>itemKey(row,landingId)===selected));
 const reason=(row:typeof rows[number],landingId:string)=>{
  if (!row.enabled) return "该线路已停用。";
  if (!listState(row).enabled) return listState(row).detail;
  const authorized=row.mode==="client"
   ? (inventory.clientChains??[]).some(chain=>chain.id===row.id&&chain.enabled&&chain.entryId===row.entryId&&chain.egressId===landingId)
   : inventory.routes.some(route=>route.enabled&&!['disabled','temporarily-suspended','policy-disabled'].includes(route.state)&&route.entryId===row.entryId&&(route.egressId===landingId||route.ipv4EgressId===landingId));
  if (!authorized || row.entryId===landingId) return "该入口与落地配对未启用测速。";
  const ready=new Set(inventory.runtimes.filter(node=>node.runtimeReady).map(node=>node.id));
  if (!ready.has(row.entryId)||!ready.has(landingId)) return "两端节点就绪后可测速。";
  const measured=routeLatency(row,landingId);
  if (measured?.latencyMs != null && measured.latencyMs > 100) return "线路参考延迟超过 100ms，无法开始测速。";
  return "";
 };
 const shareLanding=(row:typeof rows[number])=>{
  if(row.mode!=="client"||row.shared)return;
  const account=inventory.accounts.find(a=>a.account.id===row.accountId);if(!account)return;
  void save("client-chains",{shareLanding:true,accountId:row.accountId,egressId:row.egressId,expectedRevision:account.account.desiredRevision});
 };
 const toggle=(row:typeof rows[number])=>{
  const account=inventory.accounts.find(a=>a.account.id===row.accountId);if(!account)return;
  void save(row.mode==="client"?"client-chains":"routes",{...row.value,...(row.mode==="client"?{port:undefined,shared:undefined}:{state:undefined}),enabled:!row.enabled,expectedRevision:account.account.desiredRevision});
 };
 const remove=async(row:typeof rows[number])=>{
  const account=inventory.accounts.find(a=>a.account.id===row.accountId);if(!account||row.enabled)return;
  const ok=await save(row.mode==="client"?"client-chains":"routes",{...row.value,...(row.mode==="client"?{port:undefined,shared:undefined}:{state:undefined}),enabled:false,delete:true,expectedRevision:account.account.desiredRevision});
  if(ok){setDeleteKey("");setSelected("");}
 };
 return <div className="gl-split gl-route-split"><div className="gl-primary">
  <div className="gl-toolbar gl-route-toolbar">
   <label className="gl-search"><Search/><input aria-label="搜索线路" placeholder="搜索入口、落地或账户…" value={query} onChange={e=>setQuery(e.target.value)}/></label>
   <div className="gl-segment" role="group" aria-label="按线路状态筛选" title="启用表示线路开关和已知限制状态，实际连通性以检测结果为准。">{[["all","全部"],["enabled","启用"],["disabled","停用"]].map(([id,text])=><button key={id} aria-pressed={filter===id} onClick={()=>setFilter(id)}>{text}</button>)}</div>
   <SelectControl className="gl-route-mode" aria-label="筛选线路模式" value={modeFilter} onValueChange={setModeFilter} options={[{value:"all",label:"全部模式"},{value:"server",label:"转发"},{value:"client",label:"链式"}]}/>
  </div>
  {latency.error?<p role="status" className="gl-inline-error">{latency.error}</p>:null}
  {[...latency.values.values()].some(value=>value.historyUnavailable)?<p role="status" className="gl-inline-error">延迟历史暂时无法保存，重启后可能丢失；当前检测不受影响。</p>:null}
  {speed.connectionError?<p role="status" className="gl-inline-error">测速结果暂时无法更新：{speed.connectionError}</p>:null}
  <div className="gl-table-scroll"><table className="gl-data-table gl-routes"><thead><tr><th>线路</th><th>TCP 延迟</th><th>线路测速</th><th><span className="sr-only">详情</span></th></tr></thead>
   {[...groups].map(([entryId,group])=><tbody key={entryId}>
    <tr className="gl-route-group"><th colSpan={4} scope="rowgroup">入口 · {nodeName(entryId)} <span>{group.length} 组</span></th></tr>
    {group.flatMap(row=>landingIds(row).map((landingId,index)=>{
     const status=listState(row);
     const name=nodeName(landingId);
     const sameLanding=row.mode==="client"&&group.some(other=>other.mode==="client"&&other.id!==row.id&&other.accountId===row.accountId&&other.egressId===landingId);
     const meta=[inventory.accounts.length>1?accountName(row.accountId):"",sameLanding?`端口 ${row.port}`:""].filter(Boolean).join(" · ");
     return <tr key={itemKey(row,landingId)} data-selected={selected===itemKey(row,landingId)} onClick={()=>setSelected(itemKey(row,landingId))}>
      <td><div className="gl-route-heading"><span className="gl-status" data-tone={status.enabled?"good":"muted"} title={status.detail}>{status.enabled?"启用":"停用"}</span><span className="gl-route-kind" data-mode={row.mode}>{row.mode==="server"?"转发":"链式"}</span><div className="gl-route-label"><button className="gl-route-name" title={row.name||name} aria-label={row.name?`${name}，组合 ${row.name}`:name} onClick={()=>setSelected(itemKey(row,landingId))}>{name}</button>{meta?<small className="gl-route-meta" title={meta}>{meta}</small>:null}</div></div></td>
      <td><LatencyCell hideEmpty value={routeLatency(row,landingId)} now={latency.now} failed={!!latency.error}/></td>
      <td><RouteSpeedSummary test={speed.latest.get(speedKey(row.entryId,landingId))}/></td>
      <td><button className="gl-icon-button" aria-label={`查看 ${label(row)}${index>0?` · IPv4 ${nodeName(landingId)}`:""} 线路详情`} onClick={()=>setSelected(itemKey(row,landingId))}><MoreHorizontal/></button></td>
     </tr>;
    }))}
   </tbody>)}
  </table>{!shown.length?<div className="gl-empty"><Search/><h3>没有匹配的线路</h3><p>切换筛选条件，或新增一条已授权的组合。</p></div>:null}</div>
 </div>{current?<aside className="gl-inspector" data-mobile-open="true" aria-label="线路详情"><header><h2>线路详情</h2><button className="gl-icon-button" aria-label="关闭线路详情" onClick={()=>setSelected("")}><X/></button></header>
 <div className="gl-route-definitions">{[["入口",nodeName(current.entryId)],["落地",nodeName(current.egressId)],...(current.mode==="client"&&current.name?[["组合名称",current.name]]:[]),...(current.ipv4EgressId?[["IPv4 落地",nodeName(current.ipv4EgressId)]]:[]),["账户",accountName(current.accountId)],["生成模式",current.mode==="server"?"转发":"链式"],["状态",listState(current).enabled?"启用":"停用"]].map(([title,value])=><div key={title} className={title==="组合名称"?"gl-route-combination-name":undefined}><h3>{title}</h3><p title={value}>{value}</p></div>)}</div>
 <p className="gl-context-copy">{listState(current).detail}</p>
 {current.mode==="client"?<p className="gl-context-copy">仅 TCP · 落地端口 {current.port}{current.shared?" · 共享凭据":""}。停用或配置变更后，请刷新客户端订阅并验证。</p>:null}
 <details className="gl-context-details gl-route-verification"><summary>查看验证信息</summary><p>{state(current)}</p></details>
 <section className="gl-route-latencies"><h3>TCP 连接记录</h3>{landingIds(current).map(landingId=><div className="gl-route-latency-detail" key={landingId}><p>{nodeName(landingId)}</p><LatencyCell value={routeLatency(current,landingId)} now={latency.now} failed={!!latency.error}/></div>)}</section>
 {landingIds(current).map(landingId=><PathMTU key={`mtu/${current.mode}/${current.id}/${landingId}`} routeId={current.id} mode={current.mode} landingId={landingId} landingName={nodeName(landingId)} disabled={disabled}/>)}
 {landingIds(current).map(landingId=><LinkSpeed key={`${current.id}/${landingId}`} entryId={current.entryId} entryName={nodeName(current.entryId)} landingId={landingId} landingName={nodeName(landingId)} reason={reason(current,landingId)} disabled={disabled} control={speed}/>)}
 <section>{current.mode==="client"&&!current.shared?<Button className="gl-wide" variant="outline" disabled={disabled} onClick={()=>shareLanding(current)}>落地统一 24000</Button>:null}<Button className="gl-wide" variant="outline" disabled={disabled||!inventory.accounts.some(a=>a.account.id===current.accountId)} onClick={()=>toggle(current)}>{current.enabled?(listState(current).enabled?"停用线路":"关闭线路开关"):"启用线路"}</Button>
  {deleteKey===selected?<div className="gl-route-delete-confirm" role="group" aria-label="确认删除线路"><p>删除后线路将从列表和新订阅中移除，历史流量保留。{current.ipv4EgressId?"这条线路的两个落地会一并删除。":""}</p><div><Button variant="outline" disabled={disabled} onClick={()=>setDeleteKey("")}>取消</Button><Button variant="destructive" disabled={disabled||current.enabled} onClick={()=>void remove(current)}>确认删除</Button></div></div>:<Button className="gl-wide gl-route-delete-button" variant="ghost" disabled={disabled||current.enabled} onClick={()=>setDeleteKey(selected)}>删除线路</Button>}
  {current.enabled?<p className="gl-route-delete-hint">请先停用线路，待节点应用后再删除。</p>:null}
 </section>
 </aside>:null}</div>;
}
