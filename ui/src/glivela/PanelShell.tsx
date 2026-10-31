import { useState, type ReactNode } from "react";
import { Compass, Server, UserRound, Layers, Activity, Settings2, Menu, X, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
export type PanelPage = "nodes" | "accounts" | "routes" | "quality" | "diagnostics" | "settings";
const navigation = [
 { id:"nodes",label:"节点",icon:Server }, {id:"accounts",label:"账户与订阅",icon:UserRound},
 {id:"routes",label:"线路组合",icon:Layers}, {id:"quality",label:"质量与解锁",icon:ShieldCheck}, {id:"diagnostics",label:"诊断",icon:Activity},
 {id:"settings",label:"连接设置",icon:Settings2},
] as const;
export function PanelShell({page,onNavigate,subtitle,busy,onRefresh,standalone,children,actions}: {page:PanelPage;onNavigate:(page:PanelPage)=>void;subtitle:string;busy:boolean;onRefresh:()=>void;standalone:boolean;children:ReactNode;actions?:ReactNode}) {
 const [menu,setMenu]=useState(false);
 return <div className="gl-panel-host"><section data-app-workspace="vastora-official/meridian" data-standalone={standalone||undefined} data-page={page} className="glivela-control gl-workspace">
  <div className="gl-mobile-bar"><button className="gl-icon-button" aria-label={menu?"关闭导航":"打开导航"} aria-expanded={menu} aria-controls="glivela-navigation" onClick={()=>setMenu(!menu)}>{menu?<X/>:<Menu/>}</button><span>Glivela</span><button className="gl-icon-button" disabled={busy} aria-label="刷新状态" onClick={onRefresh}><RefreshCw className={busy?"gl-spinning":""}/></button></div>
  {menu?<button className="gl-nav-backdrop" aria-label="关闭导航" onClick={()=>setMenu(false)}/>:null}
  <aside className="gl-sidebar" data-open={menu}>
   <div className="gl-brand"><Compass aria-hidden="true"/><span>Glivela</span></div>
   <nav aria-label="Glivela 管理" id="glivela-navigation">{navigation.map(item=><button key={item.id} aria-current={page===item.id?"page":undefined} onClick={()=>{onNavigate(item.id);setMenu(false);}}><item.icon aria-hidden="true"/><span>{item.label}</span></button>)}</nav>
   <div className="gl-sidebar-foot">{standalone?"独立控制端":"由 Vastora 管理"}</div>
  </aside>
  <div className="gl-page">
   <header className="gl-page-header"><div><h1>{navigation.find(item=>item.id===page)?.label}</h1><p>{subtitle}</p></div><div className="gl-page-actions">{actions}<Button className={`gl-refresh ${page==="accounts"||page==="routes"?"gl-refresh-compact":""}`} aria-label="刷新状态" variant="outline" disabled={busy} onClick={onRefresh}><RefreshCw className={busy?"gl-spinning":""}/>{page==="accounts"||page==="routes"?null:"刷新状态"}</Button></div></header>
   {children}
  </div>
 </section></div>;
}
