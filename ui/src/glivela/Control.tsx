import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

type Plan = { totalBytes: string; expiryTime: string; resetDays: number; enabled: boolean };
type Account = { account: { id: string; displayName: string; desiredRevision: string; plan: Plan }; usage: { baseline: string; observed: string }[]; schedule: { nextResetAt: string }; traffic: Record<string, { uploadBytes: string; downloadBytes: string }> };
type Route = { id: string; accountId: string; entryId: string; egressId: string; ipv4EgressId?: string; enabled: boolean; hideNative: boolean; state: string };
type Runtime = { id: string; role: string; revision: string; runtimeReady: boolean; reportedAt: string; peers: string[] };
type Inventory = { state: string; accounts: Account[]; endpoints: { id: string; entryId: string; name: string; retired: boolean }[]; routes: Route[]; runtimes: Runtime[]; nodes: { id: string; name: string }[] };

// Same-origin mTLS is supplied by the browser, not a Vastora cookie or an
// application credential in JS. Never persist responses/tokens in web storage.
async function manage<T>(operation: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`/v1/admin/${operation}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal });
  if (!response.ok) throw new Error(response.status === 403 ? "管理身份未授权；请使用 Glivela 管理证书。" : "操作尚未确认，请刷新检查实际状态后重试。");
  return response.json() as Promise<T>;
}

function amount(value: string) { return `${(Number(BigInt(value) / 1048576n) / 1024).toFixed(2)} GiB`; }
function used(account: Account) { return account.usage.reduce((sum, item) => sum + BigInt(item.observed) - BigInt(item.baseline), 0n).toString(); }
const unlimited: Plan = { totalBytes: "0", expiryTime: "0", resetDays: 0, enabled: true };
const routeLabels: Record<string,string> = { verified: "当前验证通过", disabled: "已停用", "policy-disabled": "配额或账户策略停用", unverified: "待验证 / 验证过期" };

export function GlivelaControl() {
  const [inventory, setInventory] = useState<Inventory>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState("");
  const pending = useRef(false);
  const refresh = async (signal?: AbortSignal) => { setInventory(await manage<Inventory>("business", {}, signal)); };
  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal).catch((failure: unknown) => { if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : "读取失败"); });
    return () => controller.abort();
  }, []);
  const change = async (operation: string, body: unknown) => {
    if (pending.current) return false;
    pending.current = true; setBusy(true); setError(""); setNotice(""); setToken("");
    try {
      const result = await manage<{ state?: string; subscriptionToken?: string; subscriptionUrl?: string }>(operation, body);
      if (result.subscriptionUrl || result.subscriptionToken) setToken(result.subscriptionUrl ?? result.subscriptionToken ?? "");
      setNotice(operation === "business" ? "状态已刷新" : operation === "account-subscription" ? "已读取订阅链接；请私下保存，不代表线路验证通过。" : "配置已保存；节点应用和真实线路验证仍须分别通过。");
      await refresh();
      return true;
    } catch (failure) { setError(failure instanceof Error ? failure.message : "操作未确认"); return false; }
    finally { pending.current = false; setBusy(false); }
  };
  const names = new Map(inventory?.nodes.map(node => [node.id, node.name]));
  const endpointNames = new Map(inventory?.endpoints.map(endpoint => [endpoint.entryId, endpoint.name]));
  const owned = inventory?.state === "owned-unverified";
  return <section data-app-workspace="vastora-official/meridian" className="glivela-control flex flex-col gap-5 p-4 sm:p-6">
    <header className="flex flex-wrap items-center justify-between gap-3"><div><h1 className="text-xl font-semibold">Glivela</h1><p className="text-sm text-muted-foreground">独立控制端 · 配置保存不等于线路验证通过</p></div><Button disabled={busy} onClick={() => void change("business", {})}>刷新状态</Button></header>
    {error ? <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert> : null}
    {notice ? <p role="status">{notice}</p> : null}
    {!inventory ? <p role="status">正在读取…</p> : <>
      {!owned ? <Alert><AlertDescription>当前状态：{inventory.state}。需要完成离线数据接管，管理操作尚不可用；不会初始化或覆盖已有数据。</AlertDescription></Alert> : null}
      <section aria-label="节点状态"><h2 className="text-lg font-medium">节点状态</h2><Table><TableHeader><TableRow><TableHead>节点</TableHead><TableHead>角色</TableHead><TableHead>配置修订</TableHead><TableHead>运行回执</TableHead><TableHead>最后上报</TableHead></TableRow></TableHeader><TableBody>{inventory.runtimes.map(node => <TableRow key={node.id}><TableCell>{endpointNames.get(node.id) ?? names.get(node.id) ?? node.id}</TableCell><TableCell>{node.role === "entry" ? "入口" : "落地"}</TableCell><TableCell>{node.revision}</TableCell><TableCell>{node.runtimeReady ? "当前修订已应用（非整条线路证明）" : "待核验 / 上报过期"}</TableCell><TableCell>{node.reportedAt.startsWith("0001-") ? "尚无上报" : node.reportedAt}</TableCell></TableRow>)}</TableBody></Table></section>
      <section aria-label="账户与流量" className="flex flex-col gap-4"><h2 className="text-lg font-medium">账户与流量</h2>{inventory.accounts.map(account => <details key={account.account.id} className="rounded-lg border p-3"><summary className="cursor-pointer">{account.account.displayName} · 已用 {amount(used(account))} · {account.account.plan.enabled ? "启用" : "停用"}</summary><p className="my-3 text-sm text-muted-foreground">下次重置：{account.schedule.nextResetAt || "未设置"} · 用量按保留的账户账本统计，不代替供应商账单。</p><PlanEditor key={`${account.account.id}/${account.account.desiredRevision}`} initial={account.account.plan} disabled={busy || !owned} onSave={plan => change("account-plan", { accountId: account.account.id, expectedRevision: account.account.desiredRevision, plan })} /><Button className="mt-3" variant="outline" disabled={busy || !owned} onClick={() => { if (window.confirm("只重置此账户当前周期用量？原始计数、身份和历史保留。")) void change("account-reset", { accountId: account.account.id, expectedRevision: account.account.desiredRevision }); }}>重置当前周期用量</Button></details>)}</section>
      <CreateAccount inventory={inventory} disabled={busy || !owned} save={change} />
      <section aria-label="查看订阅" className="flex flex-wrap gap-2">{inventory.accounts.map(account => <Button key={account.account.id} variant="outline" disabled={busy || !owned} onClick={() => void change("account-subscription", { accountId: account.account.id })}>查看 {account.account.displayName} 的订阅链接</Button>)}</section>
      {token ? <Field><FieldLabel htmlFor="new-subscription-token">订阅链接或新账户标识（请私下保存）</FieldLabel><Input id="new-subscription-token" readOnly value={token} autoComplete="off" /></Field> : null}
      <section aria-label="双跳授权" className="flex flex-col gap-3"><h2 className="text-lg font-medium">双跳授权</h2><p className="text-sm text-muted-foreground">只选择已登记并授权的传输关系；未验证的线路不会当作可用订阅发布。</p><Table><TableHeader><TableRow><TableHead>账户</TableHead><TableHead>入口 → 落地</TableHead><TableHead>状态</TableHead><TableHead>操作</TableHead></TableRow></TableHeader><TableBody>{inventory.routes.map(route => {
        const account = inventory.accounts.find(a => a.account.id === route.accountId);
        return <TableRow key={route.id}><TableCell>{account?.account.displayName ?? route.accountId}</TableCell><TableCell>{endpointNames.get(route.entryId) ?? route.entryId} → {names.get(route.egressId) ?? route.egressId}{route.ipv4EgressId ? ` / IPv4 ${names.get(route.ipv4EgressId) ?? route.ipv4EgressId}` : ""}</TableCell><TableCell>{routeLabels[route.state] ?? "未确认"}</TableCell><TableCell><Button variant="outline" disabled={busy || !owned || !account} onClick={() => void change("routes", { ...route, state: undefined, enabled: !route.enabled, expectedRevision: account?.account.desiredRevision })}>{route.enabled ? "停用" : "启用"}</Button></TableCell></TableRow>;
      })}</TableBody></Table><CreateRoute inventory={inventory} disabled={busy || !owned} save={change} /></section>
      <p className="text-sm text-muted-foreground">卸载：先停止线路或落地的 Glivela 节点端，使用持久配置执行本地 retire-node -config，确认 Xray 已停止且所属防火墙规则已清理，再由 Vastora 保留数据卸载。退役未确认时不要删除应用。</p>
    </>}
  </section>;
}

function PlanEditor({ initial, disabled, onSave }: { initial: Plan; disabled: boolean; onSave: (plan: Plan) => Promise<boolean> }) {
  const [plan, setPlan] = useState(initial);
  return <form onSubmit={event => { event.preventDefault(); void onSave(plan); }}><FieldGroup><Field><FieldLabel>总额度（字节，0 不限）<Input required inputMode="numeric" pattern="[0-9]+" disabled={disabled} value={plan.totalBytes} onChange={event => setPlan({ ...plan, totalBytes: event.target.value })} /></FieldLabel></Field><Field><FieldLabel>到期时间（Unix 毫秒，0 不限）<Input required inputMode="numeric" pattern="[0-9]+" disabled={disabled} value={plan.expiryTime} onChange={event => setPlan({ ...plan, expiryTime: event.target.value })} /></FieldLabel></Field><Field><FieldLabel>周期天数（0 不重置）<Input type="number" min={0} max={3650} required disabled={disabled} value={plan.resetDays} onChange={event => setPlan({ ...plan, resetDays: Number(event.target.value) })} /></FieldLabel></Field><Field><FieldLabel><input type="checkbox" disabled={disabled} checked={plan.enabled} onChange={event => setPlan({ ...plan, enabled: event.target.checked })} />启用账户</FieldLabel></Field><Button type="submit" disabled={disabled}>保存账户配置</Button></FieldGroup></form>;
}

function CreateAccount({ inventory, disabled, save }: { inventory: Inventory; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean> }) {
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
  return <details className="rounded-lg border p-3"><summary className="cursor-pointer">新增账户</summary><form className="mt-3" onSubmit={event => { event.preventDefault(); if (entries.length && name.trim()) void save("accounts", { id: id.current, name: name.trim(), entryIds: entries, plan: unlimited }); }}><FieldGroup><Field><FieldLabel>名称<Input required value={name} disabled={disabled} onChange={event => setName(event.target.value)} /></FieldLabel></Field>{inventory.endpoints.filter(e => !e.retired).map(endpoint => <Field key={endpoint.id}><FieldLabel><input type="checkbox" disabled={disabled} checked={entries.includes(endpoint.entryId)} onChange={event => setEntries(event.target.checked ? [...entries, endpoint.entryId] : entries.filter(id => id !== endpoint.entryId))} />{endpoint.name}</FieldLabel></Field>)}<Button type="submit" disabled={disabled || entries.length === 0}>创建（默认不限额，随后编辑）</Button></FieldGroup></form></details>;
}

function CreateRoute({ inventory, disabled, save }: { inventory: Inventory; disabled: boolean; save: (operation: string, body: unknown) => Promise<boolean> }) {
  const id = useRef(crypto.randomUUID());
  const [accountID, setAccountID] = useState("");
  const [entryID, setEntryID] = useState("");
  const [egressID, setEgressID] = useState("");
  useEffect(() => {
    if (inventory.routes.some(item => item.id === id.current)) {
      id.current = crypto.randomUUID();
      setAccountID("");
      setEntryID("");
      setEgressID("");
    }
  }, [inventory.routes]);
  const account = inventory.accounts.find(a => a.account.id === accountID);
  const entry = inventory.runtimes.find(node => node.role === "entry" && node.id === entryID);
  return <form onSubmit={event => { event.preventDefault(); if (account && entry && entry.peers.includes(egressID)) void save("routes", { id: id.current, accountId: accountID, entryId: entryID, egressId: egressID, enabled: true, hideNative: false, expectedRevision: account.account.desiredRevision }); }}><FieldGroup><Field><FieldLabel>账户<select required disabled={disabled} value={accountID} onChange={event => setAccountID(event.target.value)}><option value="">请选择</option>{inventory.accounts.map(a => <option key={a.account.id} value={a.account.id}>{a.account.displayName}</option>)}</select></FieldLabel></Field><Field><FieldLabel>入口<select required disabled={disabled} value={entryID} onChange={event => { setEntryID(event.target.value); setEgressID(""); }}><option value="">请选择</option>{inventory.runtimes.filter(n => n.role === "entry").map(n => <option key={n.id} value={n.id}>{inventory.endpoints.find(e => e.entryId === n.id)?.name ?? n.id}</option>)}</select></FieldLabel></Field><Field><FieldLabel>已授权落地<select required disabled={disabled} value={egressID} onChange={event => setEgressID(event.target.value)}><option value="">请选择</option>{entry?.peers.map(id => <option key={id} value={id}>{inventory.nodes.find(n => n.id === id)?.name ?? id}</option>)}</select></FieldLabel></Field><Button type="submit" disabled={disabled || !account || !entry || !egressID}>新增授权</Button></FieldGroup></form>;
}
