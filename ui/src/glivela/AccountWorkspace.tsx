import { useCallback, useEffect, useState } from "react";
import { UserRound, X, ExternalLink, Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PlanEditor } from "./ControlForms";
import { SubscriptionOrderEditor } from "./SubscriptionOrder";
import { amount, used } from "./control-format";
import type { Inventory } from "./control-types";
type Save=(operation:string,body:unknown)=>Promise<boolean>;
export function AccountWorkspace({inventory,active,disabled,save,token,tokenAccountId,createdAccountId,onCreate}: {inventory:Inventory;active:boolean;disabled:boolean;save:Save;token:string;tokenAccountId:string;createdAccountId:string;onCreate:()=>void}) {
 const [selected,setSelected]=useState("");const [closed,setClosed]=useState(false);const [dirty,setDirty]=useState(false);const [pendingSelection,setPendingSelection]=useState<string|null>(null);
 const [orderDirty,setOrderDirty]=useState(false);const hasUnsaved=dirty||orderDirty;
 const orderChanged=useCallback((value:boolean)=>{setOrderDirty(value);if(!value)setPendingSelection(null);},[]);
 useEffect(()=>{if(createdAccountId){setSelected(createdAccountId);setClosed(false);setDirty(false);setOrderDirty(false);}},[createdAccountId]);
 const current=inventory.accounts.find(a=>a.account.id===selected)||inventory.accounts[0];
 const select=(id:string)=>{if(hasUnsaved&&id!==current?.account.id){setPendingSelection(id);return false;}if(id!==current?.account.id){setDirty(false);setOrderDirty(false);}setSelected(id);setClosed(false);return true;};
 const subscription=(id:string)=>{if(!select(id))return;void save("account-subscription",{accountId:id});};
 return <div className="gl-split"><div className="gl-primary">
  <div className="gl-table-scroll"><table className="gl-data-table gl-accounts"><thead><tr><th>账户名称</th><th>状态</th><th>已用流量 / 总额度</th><th>下次重置</th><th><span className="sr-only">账户操作</span></th></tr></thead><tbody>{inventory.accounts.map(item=>{
   const value=used(item), limit=BigInt(item.account.plan.totalBytes);const percentage=limit>0n?Math.min(100,Math.max(0,Number(BigInt(value)*1000n/limit)/10)):null;
   return <tr key={item.account.id} data-selected={!closed&&current?.account.id===item.account.id}>
    <td><button className="gl-node-name" onClick={()=>select(item.account.id)}><span className="gl-node-symbol"><UserRound/></span><strong>{item.account.displayName}</strong></button></td>
    <td><span className="gl-status" data-tone={item.account.plan.enabled?"good":"muted"}>{item.account.plan.enabled?"启用":"停用"}</span></td>
    <td className="gl-account-usage"><strong>{amount(value)}</strong><span> / {limit>0n?amount(item.account.plan.totalBytes):"未限额"}</span>{percentage!==null?<div className="gl-usage-track" role="progressbar" aria-label={`${item.account.displayName} 周期用量`} aria-valuenow={percentage} aria-valuemin={0} aria-valuemax={100}><span style={{width:`${percentage}%`}}/></div>:null}</td>
    <td className="gl-secondary">{item.schedule.nextResetAt&&!item.schedule.nextResetAt.startsWith("0001-")?new Date(item.schedule.nextResetAt).toLocaleDateString():"未设置"}</td>
    <td><div className="gl-row-actions"><Button variant="outline" disabled={disabled} onClick={()=>subscription(item.account.id)}>查看订阅</Button><Button variant="outline" onClick={()=>select(item.account.id)}>编辑配置</Button></div></td>
   </tr>;
  })}</tbody></table>{!inventory.accounts.length?<div className="gl-empty"><UserRound/><h3>还没有账户</h3><p>创建账户后，即可分配入口并查看订阅。</p><Button onClick={onCreate} disabled={disabled}>新增账户</Button></div>:null}</div>
 <footer className="gl-list-footer">共 {inventory.accounts.length} 个账户</footer></div>{current&&!closed?<aside className="gl-inspector gl-account-inspector" data-mobile-open={!!selected} aria-label="账户详情"><header><div><h2>{current.account.displayName}</h2><span className="gl-status" data-tone={current.account.plan.enabled?"good":"muted"}>{current.account.plan.enabled?"启用":"停用"}</span></div><button className="gl-icon-button" aria-label="关闭账户详情" onClick={()=>{if(hasUnsaved){setPendingSelection("@close");return;}setDirty(false);setOrderDirty(false);setClosed(true);setSelected("");}}><X/></button></header>
 {pendingSelection?<div className="gl-unsaved" role="alert"><h3>有未保存的更改</h3><p>当前账户的更改还没有保存。</p><div><Button variant="outline" onClick={()=>setPendingSelection(null)}>继续编辑</Button><Button onClick={()=>{setDirty(false);setOrderDirty(false);if(pendingSelection==="@close"){setSelected("");setClosed(true);}else {setSelected(pendingSelection);setClosed(false);}setPendingSelection(null);}}>放弃更改{pendingSelection==="@close"?"并关闭":"并切换"}</Button></div></div>:null}
 <section className="gl-account-editor"><label className="gl-readonly-field">账户名称<Input readOnly value={current.account.displayName} title="当前接口不提供账户改名"/></label><PlanEditor key={`${current.account.id}/${current.account.desiredRevision}`} initial={current.account.plan} disabled={disabled} onDirtyChange={value=>{setDirty(value);if(!value)setPendingSelection(null);}} onSave={plan=>save("account-plan",{accountId:current.account.id,expectedRevision:current.account.desiredRevision,plan})}/></section>
 <section><h3>重置当前周期用量</h3><p>仅重置当前周期，保留原始计数、身份与历史。</p><Button className="gl-wide" variant="outline" disabled={disabled} onClick={()=>{if(window.confirm("只重置此账户当前周期用量？原始计数、身份和历史保留。"))void save("account-reset",{accountId:current.account.id,expectedRevision:current.account.desiredRevision});}}>重置当前周期用量</Button></section>
 <SubscriptionOrderEditor key={current.account.id} accountId={current.account.id} active={active} disabled={disabled} save={save} onDirtyChange={orderChanged}/>
 <section><h3><Link2/>订阅访问</h3><p>订阅链接含访问凭据，请私下保存。</p><Button variant="outline" className="gl-wide" disabled={disabled} onClick={()=>subscription(current.account.id)}><ExternalLink/>查看订阅链接</Button>{token&&tokenAccountId===current.account.id?<label className="gl-secret-field">订阅链接或新账户标识<Input aria-label="订阅链接或新账户标识" readOnly value={token} autoComplete="off"/></label>:null}</section>
 </aside>:null}</div>;
}
