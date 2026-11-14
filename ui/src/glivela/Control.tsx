import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { type SpeedBody, type SpeedList } from "./LinkSpeed";
import { useRouteLatencies, type RouteLatency } from "./RouteLatency";
import { NetworkPanel, useNetworkOptimization } from "./NetworkOptimization";
import { RealityTarget } from "./RealityTarget";
import { useControlRequest } from "./ControlAccess";
import { hostNames } from "./control-format";
import type { Inventory } from "./control-types";
import { PanelShell, type PanelPage } from "./PanelShell";
import { NodeWorkspace } from "./NodeWorkspace";
import { AccountWorkspace } from "./AccountWorkspace";
import { RouteWorkspace } from "./RouteWorkspace";
import { AvailabilityEditor, CreateAccount, CreateRoute } from "./ControlForms";
import { IPQuality, useIPQuality } from "./IPQuality";
import "./Panel.css";

export function GlivelaControl({standalone=false, agents=[]}: {standalone?:boolean; agents?: {id: string; name: string}[]}) {
  const manage = useControlRequest();
  const loadSpeeds = useCallback((body: SpeedBody, signal?: AbortSignal) => manage<SpeedList>("link-speeds", body, signal), [manage]);
  const loadRouteLatencies = useCallback((body: { refresh: boolean; force: boolean }, signal: AbortSignal) => manage<{ latencies: RouteLatency[] }>("route-latencies", body, signal), [manage]);
  const [inventory, setInventory] = useState<Inventory>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState("");
  const [tokenAccountId,setTokenAccountId]=useState("");
  const pending = useRef(false);
  const refresh = async (signal?: AbortSignal) => { setInventory(await manage<Inventory>("business", {}, signal)); };
  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal).catch((failure: unknown) => { if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : "读取失败"); });
    return () => controller.abort();
  }, [manage]);
  const change = async (operation: string, body: unknown) => {
    if (pending.current) return false;
    pending.current = true; setBusy(true); setError(""); setNotice(""); setToken(""); setTokenAccountId("");
    try {
      const result = await manage<{ state?: string; subscriptionToken?: string; subscriptionUrl?: string }>(operation, body);
      if (result.subscriptionUrl || result.subscriptionToken) { setToken(result.subscriptionUrl ?? result.subscriptionToken ?? ""); const subject=body&&typeof body==="object"?body as Record<string,unknown>:{};setTokenAccountId(typeof subject.accountId==="string"?subject.accountId:typeof subject.id==="string"?subject.id:""); }
      setNotice(operation === "business" ? "状态已刷新" : operation === "subscription-order" ? "订阅顺序已保存，OpenClash 刷新订阅后生效。" : operation === "account-subscription" ? "已读取订阅链接；请私下保存，不代表线路验证通过。" : operation === "retire-landing" ? "落地身份已撤销，专属链式和诊断已清理；未登录或卸载退租主机。" : operation === "retire-returned-entry" ? "入口身份已撤销，专属线路与密钥已清理；历史归档和备份尚需另行确认。" : operation === "retire-entry" ? "入口已从控制端退役；离线主机的停止与清理尚未验证。" : (operation === "routes" || operation === "client-chains") && body && typeof body === "object" && "delete" in body && body.delete === true ? "线路已删除，请刷新客户端订阅。" : "配置已保存；节点应用和真实线路验证仍须分别通过。");
      await refresh();
      return true;
    } catch (failure) { setError(failure instanceof Error ? failure.message : "操作未确认"); return false; }
    finally { pending.current = false; setBusy(false); }
  };
  const names = useMemo(()=>inventory ? hostNames(inventory, agents) : new Map<string,string>(),[inventory, agents]);
  const owned = inventory?.state === "owned";
  const latency = useRouteLatencies(owned, loadRouteLatencies);
  const network = useNetworkOptimization(!!inventory);
  const [networkNode, setNetworkNode] = useState("");

 const [page,setPage]=useState<PanelPage>("nodes");
 const quality=useIPQuality(!!inventory&&(page==="nodes"||page==="quality"));
 const [dialog,setDialog]=useState<"account"|"route"|"availability"|null>(null);
 const [pauseNode,setPauseNode]=useState("");
 const [createdAccountId,setCreatedAccountId]=useState("");
 const saveDialog=async(operation:string,body:unknown)=>{const ok=await change(operation,body);if(ok){setDialog(null);if(operation==="accounts"){setPage("accounts");setCreatedAccountId((body as {id:string}).id);}else if(operation==="routes"||operation==="client-chains")setPage("routes");}return ok;};
 const disabled=busy||!owned;
 const applied=inventory?.runtimes.filter(n=>n.runtimeReady).length??0;
 const subtitles={nodes:inventory?`${new Set(inventory.runtimes.map(node=>node.hostId||node.id)).size} 个节点 · ${applied} 个角色已应用 · ${inventory.runtimes.length-applied} 个角色待核验`:"读取节点运行状态",accounts:"管理账户额度与订阅访问",routes:"管理入口与落地之间的订阅授权",quality:"查看实际出口评分、解锁状态与检测时间",diagnostics:"检查线路与节点状态",settings:"管理 REALITY 目标与连接配置"};
 return <PanelShell page={page} onNavigate={next=>{setPage(next);setNotice("");setToken("");setTokenAccountId("");}} subtitle={subtitles[page]} busy={busy} onRefresh={()=>void change("business",{})} standalone={standalone} actions={inventory&&page==="accounts"?<Button disabled={disabled} onClick={()=>setDialog("account")}><Plus/>新增账户</Button>:inventory&&page==="routes"?<Button disabled={disabled} onClick={()=>setDialog("route")}><Plus/>新增线路</Button>:undefined}>
  {error?<Alert variant="destructive" className="gl-message"><AlertDescription>{error}</AlertDescription></Alert>:null}
  {notice?<p role="status" className="gl-message gl-notice">{notice}</p>:null}
  {!inventory?<div className="gl-empty" role="status"><p>{error?"未能读取面板数据，请点击刷新状态重试。":"正在读取…"}</p></div>:<>
   {!owned?<Alert className="gl-message"><AlertDescription>当前状态：{inventory.state}。需要完成离线数据接管，管理操作尚不可用；不会初始化或覆盖已有数据。</AlertDescription></Alert>:null}
   <div className="gl-tab-body" hidden={page!=="nodes"}><NodeWorkspace onEgressSaved={() => refresh()} inventory={inventory} names={names} agents={agents} onBind={(nodeId,expectedAgentId,agentId)=>change("host-binding",{nodeId,expectedAgentId,agentId})} quality={quality} network={network} disabled={disabled} onNetwork={setNetworkNode} onPause={id=>{setPauseNode(id);setDialog("availability");}} onRetireReturnedEntry={(id,confirmation,confirmHostReturned)=>{const node=inventory.runtimes.find(n=>n.id===id);const availability=inventory.availability;return node?.certificateId&&availability?change("retire-returned-entry",{id,certificateId:node.certificateId,expectedRevision:node.revision,expectedAvailabilityRevision:availability.revision,confirmation,confirmHostReturned}):Promise.resolve(false);}} onRetireLanding={(id,confirmation,confirmHostReturned)=>{const node=inventory.runtimes.find(n=>n.id===id);const availability=inventory.availability;return node?.certificateId&&availability?change("retire-landing",{id,certificateId:node.certificateId,expectedRevision:node.revision,expectedAvailabilityRevision:availability.revision,confirmation,confirmHostReturned}):Promise.resolve(false);}} onRetire={id=>{const node=inventory.runtimes.find(n=>n.id===id);const availability=inventory.availability;if(node&&availability)void change("retire-entry",{id,expectedRevision:node.revision,expectedAvailabilityRevision:availability.revision});}}/></div>
   <div className="gl-tab-body" hidden={page!=="accounts"}><AccountWorkspace inventory={inventory} active={page==="accounts"} disabled={disabled} save={change} token={token} tokenAccountId={tokenAccountId} createdAccountId={createdAccountId} onCreate={()=>setDialog("account")}/></div>
   <div className="gl-tab-body" hidden={page!=="routes"}><RouteWorkspace inventory={inventory} names={names} disabled={disabled} save={change} latency={latency} loadSpeeds={loadSpeeds} active={page==="routes"}/></div>
   <div className="gl-tab-body gl-settings-body" hidden={page!=="quality"}><IPQuality control={quality} names={names}/></div>
   <div className="gl-tab-body gl-settings-body" hidden={page!=="diagnostics"}><div className="gl-settings-section"><AvailabilityEditor inventory={inventory} names={names} disabled={disabled} save={change}/></div></div>
   <div className="gl-tab-body gl-settings-body" hidden={page!=="settings"}><RealityTarget endpoints={inventory.endpoints} names={names} disabled={disabled}/><details className="gl-maintenance"><summary>维护与卸载</summary><p>先停止线路或落地的 Glivela 节点端，使用持久配置执行本地 retire-node -config，确认 Xray 已停止且所属防火墙规则已清理，再由 Vastora 保留数据卸载。退役未确认时不要删除应用。</p></details></div>
   {dialog?<Sheet open onOpenChange={open=>{if(!open)setDialog(null);}}><SheetContent className="gl-panel-sheet overflow-y-auto" data-standalone={standalone||undefined}><SheetHeader><SheetTitle>{dialog==="account"?"新增账户":dialog==="route"?"新增线路":"临时停用与恢复验证"}</SheetTitle><SheetDescription>{dialog==="account"?"选择此账户可使用的入口。":dialog==="route"?"只选择已登记并授权的传输关系。":"保留配置、身份、授权和账本。"}</SheetDescription></SheetHeader><div className="gl-dialog-body">{dialog==="account"?<CreateAccount inventory={inventory} names={names} disabled={disabled} save={saveDialog}/>:dialog==="route"?<CreateRoute inventory={inventory} names={names} disabled={disabled} save={saveDialog} latencies={latency.values} now={latency.now} latencyFailed={!!latency.error}/>:<AvailabilityEditor key={pauseNode} inventory={inventory} names={names} disabled={disabled} save={saveDialog} initialNodeID={pauseNode} expanded/>}</div></SheetContent></Sheet>:null}
   {network.error&&page==="nodes"?<p role="status" className="gl-message gl-secondary">{network.error}</p>:null}
   {networkNode?<NetworkPanel nodeId={networkNode} name={names.get(networkNode)??networkNode} control={network} onClose={()=>setNetworkNode("")}/>:null}
  </>}
 </PanelShell>;
}
