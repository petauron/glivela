import { useEffect, useId, useState } from "react";
import { Trash2Icon } from "lucide-react";
import { api } from "@/api";
import type { AppData, Mutate } from "@/App";
import type { LandingView } from "@/landing-types";
import type { Language } from "@/translations";
import { SelectControl } from "@/components/SelectControl";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { StateBadge, copy, userError } from "@/views/shared";
import { RouteHealth } from "./RouteHealth";

type CompositeGrant = AppData["meridian"]["grants"][number] & { ipv4EgressNodeId?: string; ipv4EgressNodeName?: string };
const ipv6Exit = (server: LandingView["servers"][number]) => Boolean(server.egressIp?.includes(":") && !server.egressIp?.toLowerCase().startsWith("::ffff:"));

export function MeridianRoutes({ data, language, mutate, endpointId: fixedEntry, egressNodeId: fixedExit, landingServers }: {
  data: AppData; language: Language; mutate: Mutate; endpointId?: string; egressNodeId?: string; landingServers?: LandingView["servers"];
}) {
  const id = useId();
  const accounts = data.meridian.accounts.filter((account) => account.enabled);
  const [account, setAccount] = useState(accounts.length === 1 ? accounts[0].id : "");
  const [entry, setEntry] = useState(fixedEntry ?? "");
  const [exit, setExit] = useState(fixedExit ?? "");
  const [composite, setComposite] = useState(false);
  const [ipv4Exit, setIPv4Exit] = useState("");
  const [hideNative, setHideNative] = useState(false);
  const [servers, setServers] = useState<LandingView["servers"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    if (landingServers) return;
    let active = true;
    setServers(null);
    setError("");
    void api.landing().then((value) => { if (active) setServers(value.servers); }).catch((cause) => { if (active) setError(userError(language, cause)); });
    return () => { active = false; };
  }, [reload, language, landingServers]);
  const availableServers = landingServers ?? servers;
  const entries = data.meridian.endpoints.filter((value) => value.vless && value.status === "ready" && value.nodeId !== exit && (!composite || value.nodeId !== ipv4Exit));
  const entryNode = data.meridian.endpoints.find((item) => item.id === entry)?.nodeId;
  const exits = availableServers?.filter((value) => value.status === "ready" && value.nodeId !== entryNode && (!composite || ipv6Exit(value))) ?? [];
  const ipv4Exits = availableServers?.filter((value) => value.status === "ready" && value.nodeId !== entryNode && value.nodeId !== exit && !ipv6Exit(value)) ?? [];
  const grants = (data.meridian.grants as CompositeGrant[]).filter((grant) => (!fixedEntry || grant.endpointId === fixedEntry) && (!fixedExit || grant.egressNodeId === fixedExit || grant.ipv4EgressNodeId === fixedExit));
  const exists = grants.some((grant) => grant.accountId === account && grant.endpointId === entry && grant.egressNodeId === exit && (grant.ipv4EgressNodeId ?? "") === (composite ? ipv4Exit : ""));
  const managementReady = data.meridian.cutover.subscriptionAuthority === "meridian" && ["not_required", "complete"].includes(data.meridian.cutover.state);
  const ready = managementReady && accounts.some((value) => value.id === account) && entries.some((value) => value.id === entry) && exits.some((value) => value.nodeId === exit) && (!composite || ipv4Exits.some((value) => value.nodeId === ipv4Exit));
  const run = async (operation: () => Promise<unknown>, message: string) => {
    if (busy) return;
    setBusy(true); setError("");
    try { await mutate(operation, message); } catch (cause) { setError(userError(language, cause)); } finally { setBusy(false); }
  };
  return <section className="flex min-w-0 flex-col gap-3 text-xs" aria-label={copy(language, "订阅线路", "Subscription routes")}>
    {!fixedExit ? <h4 className="font-medium">{copy(language, "加入订阅", "Add to subscription")}</h4> : null}
    <form onSubmit={(event) => { event.preventDefault(); const input = { accountId: account, endpointId: entry, egressNodeId: exit, ipv4EgressNodeId: composite ? ipv4Exit : undefined, hideNative }; if (ready && !exists) void run(() => api.createMeridianRoute(input), copy(language, "线路已添加，正在配置。", "Route added; configuring.")); }}>
      <FieldGroup className="mb-3 gap-3">
        <Field>
          <FieldLabel htmlFor={`${id}-mode`}>{copy(language, "出口方式", "Exit mode")}</FieldLabel>
          <SelectControl id={`${id}-mode`} size="sm" value={composite ? "composite" : "fixed"} onValueChange={(value) => { setComposite(value === "composite"); setIPv4Exit(""); if (!fixedExit && value === "composite" && !availableServers?.some((server) => server.nodeId === exit && ipv6Exit(server))) setExit(""); }} disabled={busy} options={[{ value: "fixed", label: copy(language, "固定落地", "Fixed exit") }, { value: "composite", label: copy(language, "IPv6 优先组合", "IPv6-priority composite"), disabled: Boolean(fixedExit && !availableServers?.some((server) => server.nodeId === fixedExit && ipv6Exit(server))) }]} />
          {composite ? <FieldDescription id={`${id}-policy`}>{copy(language, "使用官方 Xray，按 DNS 返回结果优先走 IPv6，没有 IPv6 结果时走指定 IPv4。仅支持 TCP，共用账号流量额度；连接失败不切换落地，两台均就绪后发布。", "Official Xray prefers IPv6 in the DNS results and uses the selected IPv4 exit when no IPv6 result is available. TCP only; one shared quota. Connection failure never switches exits. Both exits must be ready before publication.")}</FieldDescription> : null}
        </Field>
        {composite ? <Field><FieldLabel htmlFor={`${id}-ipv4`}>{copy(language, "IPv4 补充落地", "Secondary IPv4 exit")}</FieldLabel><SelectControl id={`${id}-ipv4`} aria-describedby={`${id}-policy`} size="sm" value={ipv4Exit} onValueChange={setIPv4Exit} disabled={busy || !availableServers} options={[{ value: "", label: copy(language, "选择独立 IPv4 落地", "Choose distinct IPv4 exit"), disabled: true }, ...ipv4Exits.map((value) => ({ value: value.nodeId, label: value.name }))]} /></Field> : null}
      </FieldGroup>
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex min-w-36 flex-1 flex-col gap-1.5"><span>{copy(language, "账号", "Account")}</span><SelectControl className="h-8" aria-label={copy(language, "订阅账号", "Subscription account")} value={account} onValueChange={setAccount} disabled={busy} options={[{ value: "", label: copy(language, "选择账号", "Choose account"), disabled: true }, ...accounts.map((value) => ({ value: value.id, label: value.displayName }))]} /></label>
        {!fixedEntry ? <label className="flex min-w-36 flex-1 flex-col gap-1.5"><span>{copy(language, "线路机", "Entry node")}</span><SelectControl className="h-8" aria-label={copy(language, "线路机", "Entry node")} value={entry} onValueChange={setEntry} disabled={busy} options={[{ value: "", label: copy(language, "选择线路机", "Choose entry"), disabled: true }, ...entries.map((value) => ({ value: value.id, label: value.displayName || data.agents.find((agent) => agent.id === value.nodeId)?.name || value.applicationName }))]} /></label> : null}
        {!fixedExit ? <label className="flex min-w-36 flex-1 flex-col gap-1.5"><span>{copy(language, composite ? "IPv6 主落地" : "落地机", composite ? "Primary IPv6 exit" : "Exit node")}</span><SelectControl className="h-8" aria-label={copy(language, composite ? "IPv6 主落地" : "落地机", composite ? "Primary IPv6 exit" : "Exit node")} value={exit} onValueChange={setExit} disabled={busy || !availableServers} options={[{ value: "", label: copy(language, "选择落地机", "Choose exit"), disabled: true }, ...exits.map((value) => ({ value: value.nodeId, label: value.name }))]} /></label> : null}
        <Button className="h-8 shrink-0" size="sm" type="submit" disabled={busy || !ready || exists}>{busy ? copy(language, "正在保存…", "Saving…") : exists ? copy(language, "已添加", "Added") : copy(language, "加入订阅", "Add to subscription")}</Button>
      </div>
      {!accounts.length ? <p className="mt-2 text-muted-foreground">{copy(language, "请先在“账号与订阅”中创建账号。", "Create an account in Accounts & subscriptions first.")}</p> : null}
      {composite && availableServers && !exits.length ? <p className="mt-2 text-muted-foreground">{copy(language, "需要一台已应用 IPv6 出口地址的独立落地。", "An independent landing with an applied IPv6 egress address is required.")}</p> : null}
      {composite && availableServers && !ipv4Exits.length ? <p className="mt-2 text-muted-foreground">{copy(language, "需要另一台已就绪的 IPv4 落地，不能使用入口或 IPv6 主落地。", "A separate ready IPv4 exit is required; neither the entry nor the IPv6 exit can be reused.")}</p> : null}
      <details className="mt-3 text-muted-foreground"><summary className="w-fit cursor-pointer">{copy(language, "高级选项", "Advanced")}</summary><div className="mt-2 flex items-center gap-2"><Switch id={`${id}-native`} checked={hideNative} onCheckedChange={setHideNative} disabled={busy} /><label htmlFor={`${id}-native`}>{copy(language, "隐藏直连 VLESS", "Hide direct VLESS")}</label></div></details>
    </form>
    {error ? <p role="alert" className="text-destructive">{error}{availableServers === null ? <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}>{copy(language, "重试", "Retry")}</Button> : null}</p> : null}
    {grants.length ? <details className="border-t pt-2">
      <summary className="w-fit cursor-pointer text-muted-foreground">{copy(language, `已添加 ${grants.length} 条线路`, `${grants.length} added routes`)}</summary>
      <div className="mt-2 divide-y">{grants.map((grant) => <div className="flex min-w-0 flex-col gap-2 py-2" key={grant.id}>
        <div className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate" title={grant.ipv4EgressNodeId ? `${grant.egressNodeName} (IPv6) / ${grant.ipv4EgressNodeName ?? grant.ipv4EgressNodeId} (IPv4)` : grant.egressNodeName}>
            {data.meridian.accounts.find((value) => value.id === grant.accountId)?.displayName} · {data.meridian.endpoints.find((value) => value.id === grant.endpointId)?.displayName} → {grant.ipv4EgressNodeId ? copy(language, "IPv6 优先 + IPv4", "IPv6 priority + IPv4") : grant.egressNodeName}
          </span>
          <StateBadge language={language} value={grant.status} />
          <Button size="icon-sm" variant="ghost" aria-label={copy(language, "移除订阅线路", "Remove subscription route")} disabled={busy || grant.status === "revoking"} onClick={() => void run(() => api.revokeMeridianRoute(grant.id), copy(language, "正在移除线路。", "Removing route."))}><Trash2Icon data-icon="inline-start" /></Button>
          {grant.lastError ? <span className="text-destructive">{copy(language, grant.status === "blocked" ? "链路未验证" : "配置失败", grant.status === "blocked" ? "Transport unverified" : "Failed")}</span> : null}
        </div>
        <RouteHealth routeId={grant.id} language={language} primaryName={grant.egressNodeName} ipv4Name={grant.ipv4EgressNodeName} />
      </div>)}</div>
    </details> : null}
  </section>;
}
