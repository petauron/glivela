import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectControl } from "@/components/SelectControl";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { useControlRequest } from "./ControlAccess";

type Endpoint = { entryId: string; name: string; retired: boolean };
type Change = { initialRepair?: { evidenceSha256: string; verifiedAt: string }; target: string; targetIp: string; serverName: string; state: string; changedAt: string; revertedAt?: string; reason?: string };
type View = { repairInitial: boolean; certificateId: string; configSha256: string; previewLink?: string; previewMihomo?: string; entryId: string; revision: string; target: string; serverNames: string[]; state: string; runtimeReady: boolean; history: Change[] };

export function RealityTarget({ endpoints, names, disabled }: { endpoints: Endpoint[]; names: Map<string, string>; disabled: boolean }) {
 const fieldID=useId();
 const manage=useControlRequest();
 const [entry,setEntry]=useState("");
 const [view,setView]=useState<View>();
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [target,setTarget]=useState("");
 const [ip,setIP]=useState("");
 const [localOrigin,setLocalOrigin]=useState(false);
 const [sni,setSNI]=useState("");
 const [reason,setReason]=useState("");
 const [evidence,setEvidence]=useState("");
 const [verifiedAt,setVerifiedAt]=useState("");
 const [checked,setChecked]=useState(false);
 const repairing=view?.repairInitial===true;
 const pending=view?.state==="pending" || view?.state==="reverting";
 const request=async(action:string)=>{
  if(busy || disabled || !entry || action==="repair-initial" && (!repairing || !checked))return;
  setBusy(true);setError("");
  try {
   const next=await manage<View>("reality-target",{entryId:entry,expectedRevision:view?.revision??"0",action,
    ...(action==="apply"?{targetHost:localOrigin?sni.trim():target.trim(),targetIp:localOrigin?"":ip.trim(),serverName:sni.trim(),localTlsOrigin:localOrigin}:{}),
    ...(action==="repair-initial"?{initialRepair:{certificateId:view?.certificateId,configSha256:view?.configSha256,evidenceSha256:evidence.trim(),verifiedAt:new Date(verifiedAt).toISOString()}}:{}),
    ...(action==="revert"?{reason:reason.trim()}:{}),
    ...(action==="accept"?{publicationChecked:checked,evidenceSha256:evidence.trim(),verifiedAt:new Date(verifiedAt).toISOString()}:{}),
   });
   setView(next);setChecked(false);setEvidence("");setVerifiedAt("");
  } catch {setError("操作未确认。请刷新当前状态；不要重复提交或修改运行文件。普通目标变更失败时可以撤销；首次登记纠正不能恢复无效旧端口。配置漂移须先恢复受管配置归属。");}
  finally {setBusy(false);}
 };
 return <details open className="gl-settings-section"><summary className="cursor-pointer">REALITY 目标与 SNI</summary>
  <p className="my-3 text-sm text-muted-foreground">修改会让该入口短暂重连。保留账户、订阅身份、密钥和流量计数；待验收期间，该入口及其组合暂不进入新订阅，已缓存订阅请及时刷新。</p>
  <FieldGroup><Field><FieldLabel htmlFor={fieldID}>入口</FieldLabel><SelectControl id={fieldID} aria-label="入口" disabled={disabled||busy} value={entry} onValueChange={value=>{setEntry(value);setView(undefined);setChecked(false);setError("");}} placeholder="请选择" options={endpoints.filter(e=>!e.retired).map(e=>({value:e.entryId,label:names.get(e.entryId) ?? e.entryId}))}/></Field>
  <Button type="button" variant="outline" disabled={disabled||busy||!entry} onClick={()=>void request("inspect")}>{busy?"正在处理…":"读取 / 刷新目标状态"}</Button>
  {error?<p role="alert" className="text-sm text-destructive">{error}</p>:null}
  {view?<><p role="status" className="text-sm">当前目标：{view.target} · SNI：{view.serverNames.join(" / ")} · {view.runtimeReady?"节点当前修订验证通过":"等待当前修订的真实节点验证"} · {view.state}</p>
   <p className="text-sm text-muted-foreground">共享 443：先在 Vastora 现有访问入口中准备新 SNI 路由，保留原路由以便恢复。节点应用通过后，完成正式发布检查并用下面的候选测试链接做实际 HTTPS 验收，再记录下面的人工验收。这里不会自动修改 HAProxy，也不会把 TLS 预检当作代理可用证明。</p>
   {view.previewLink?<details><summary>候选测试链接（含现有用户身份，仅私下使用）</summary><p className="my-2 text-sm text-muted-foreground">请在可信客户端导入此临时测试链接，验证正式公网入口的 HTTPS 访问与预期出口。它不进入正式订阅，不生成新账户。测试完成后从客户端删除；不要放入日志、公开 Issue 或截图。</p><Input aria-label="候选测试链接" readOnly value={view.previewLink}/>{view.previewMihomo?<Field><FieldLabel>Mihomo 候选配置（保留当前 REALITY 握手选项）<textarea readOnly rows={6} className="w-full rounded-md border p-2 font-mono text-xs" value={view.previewMihomo}/></FieldLabel></Field>:null}</details>:null}
   {repairing?<form onSubmit={event=>{event.preventDefault();void request("repair-initial");}} className="flex flex-col gap-3">
    <p className="text-sm">首次登记的同机站点端口无效。可以保留原域名与身份，只纠正为固定受管端口；节点校验和公网访问验收通过前不会加入正式订阅。</p>
    <details><summary>运维核对信息</summary><p className="text-sm break-all">节点证书指纹：{view.certificateId}<br/>当前配置摘要：{view.configSha256}</p></details>
    <Field><FieldLabel>节点核验记录 SHA256<Input required pattern="[a-f0-9]{64}" value={evidence} onChange={e=>setEvidence(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
    <Field><FieldLabel>节点核验时间<Input required type="datetime-local" step="1" value={verifiedAt} onChange={e=>setVerifiedAt(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
    <label className="flex gap-2 text-sm"><input type="checkbox" required checked={checked} onChange={e=>setChecked(e.target.checked)} disabled={busy||disabled}/>已通过认证连接核对同一节点、证书及配置，确认没有已激活或恢复中的运行记录、代理进程或监听，并已停止该节点的管理进程直至纠正完成。</label>
    <p className="text-sm text-muted-foreground">这是运维人员的核验声明，系统不会读取外部记录。请填写 15 分钟内的真实核验时间，私下保留详细记录。纠正成功后再启动该节点的管理进程并刷新状态。</p>
    <Button disabled={busy||disabled||!checked} type="submit">纠正首次登记端口</Button>
   </form>:!pending?<form onSubmit={event=>{event.preventDefault();void request("apply");}} className="flex flex-col gap-3">
    <label className="flex gap-2 text-sm"><input type="checkbox" checked={localOrigin} onChange={e=>setLocalOrigin(e.target.checked)} disabled={busy||disabled}/>使用同机的 Vastora 受管站点</label>
    {localOrigin?<p className="text-sm text-muted-foreground">先在本节点发布 HTTPS 网站并准备对应 SNI 路由。将使用固定本机 TLS 后端，节点仍会检查站点证书和实际代理连接。</p>:<>
    <Field><FieldLabel>目标域名<Input required maxLength={253} value={target} onChange={e=>setTarget(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
    <Field><FieldLabel>已审核的固定公网 IP<Input required maxLength={45} value={ip} onChange={e=>setIP(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
    </>}
    <Field><FieldLabel>精确 SNI<Input required maxLength={253} value={sni} onChange={e=>setSNI(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
    <Button disabled={busy||disabled||!view.runtimeReady} type="submit">应用目标，等待节点及公网验收</Button>
   </form>:<>
    {view.state==="pending" && !view.history.at(-1)?.initialRepair?<form className="flex flex-col gap-3" onSubmit={event=>{event.preventDefault();void request("revert");}}><Field><FieldLabel>撤销原因<Input required maxLength={256} value={reason} onChange={e=>setReason(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field><Button variant="outline" disabled={busy||disabled} type="submit">以新修订恢复上次目标</Button><p className="text-sm text-muted-foreground">不会回滚账本或降低修订。恢复原共享 SNI 路由后仍须完成节点和公网验收。</p></form>:null}
    {view.history.at(-1)?.initialRepair?<p className="text-sm text-muted-foreground">端口已纠正，旧错误端口不能恢复。请启动该节点的管理进程，等待节点应用并完成实际访问验收；失败时检查同机站点状态。</p>:null}
    <form className="flex flex-col gap-3" onSubmit={event=>{event.preventDefault();void request("accept");}}>
     <Field><FieldLabel>私下保留的验收记录 SHA256<Input required pattern="[a-f0-9]{64}" value={evidence} onChange={e=>setEvidence(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
     <Field><FieldLabel>实际验收时间<Input required type="datetime-local" step="1" value={verifiedAt} onChange={e=>setVerifiedAt(e.target.value)} disabled={busy||disabled}/></FieldLabel></Field>
     <label className="flex gap-2 text-sm"><input type="checkbox" required checked={checked} onChange={e=>setChecked(e.target.checked)} disabled={busy||disabled}/>已完成适用的正式发布检查及实际认证客户端 HTTPS 验收，记录不含凭据或完整订阅链接。</label>
     <p className="text-sm text-muted-foreground">这是管理员人工验收声明，系统不会读取或独立验证外部记录内容；节点自己的就绪校验仍必须通过。请填写 15 分钟内的真实验收时间。</p>
     <Button disabled={busy||disabled||!view.runtimeReady||!checked} type="submit">记录人工验收并恢复订阅发布</Button>
    </form>
   </>}
   {view.history.length?<details><summary>目标变更记录</summary><ul>{view.history.map((c,i)=><li key={`${c.changedAt}-${i}`} className="my-2 text-sm">{c.changedAt} · {c.target} · {c.serverName} · {c.state}{c.initialRepair?" · 首次登记端口纠正":""}{c.reason?` · 撤销原因：${c.reason}`:""}</li>)}</ul></details>:null}
  </>:null}</FieldGroup>
 </details>;
}
