import { useState } from "react";
import { EllipsisIcon, SearchIcon } from "lucide-react";
import type { AppWorkspaceProps } from "@/app-workspaces/types";
import { DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useIPQuality } from "@/views/IPQuality";
import { LandingNotice, useLanding } from "@/views/LandingControls";
import { LandingTableRows } from "./LandingNodes";
import { NodeLocation } from "./NodeLocation";
import { RegionFlag } from "./RegionFlag";
import { ApplicationPrimaryStatus } from "@/views/apps/InstalledApplicationPrimitives";
import { api } from "@/api";
import type { InstalledAppInstance } from "@/views/installed-apps-model";
import { publicationNeedsAttention, showInstalledNode } from "@/views/installed-apps-model";
import { catalogInstallBlocked, copy } from "@/views/shared";
import { GlivelaTrafficPanel } from "./Traffic";
import { GlivelaLinkTests } from "./LinkTests";
import { SelectControl } from "@/components/SelectControl";
import { ipQualityCheckForAddress } from "@/views/ipQualityModel";
import { compareSelection, entryAvailable, entryState, matchesEntryPurpose } from "./selection";
import { NodeQualityCells, UnlockHeaders, nodeTableColumns } from "./NodeQuality";
import { GlivelaUpdates } from "./Updates";
import { QualityNotice, UnlockLegend } from "./QualityNotice";
import { manifest } from "./manifest";

export function GlivelaWorkspace({ group, data, language, mutate, onManage, onUpgrade, onClients, showSite }: AppWorkspaceProps) {
  const landing = useLanding();
  const [entryId, setEntryId] = useState("");
  const [landingId, setLandingId] = useState("");
  const compareRoute = (entry: string, exit: string) => { setEntryId(entry); setLandingId(exit); setPage("network"); };
  const [query, setQuery] = useState("");
  const [page, setPage] = useState<string>(manifest.pages[0].id);
  const quality = useIPQuality();
  const [purpose, setPurpose] = useState("all");
  const [order, setOrder] = useState("quality");
  const checkFor = (instance: InstalledAppInstance) => quality?.error ? undefined : ipQualityCheckForAddress(quality?.checks ?? [], instance.application.nodeId, instance.agent?.publicEgress?.address ?? "");
  const search = query.trim().toLocaleLowerCase();
  const entries = group.instances.filter(showInstalledNode);
  const instances = entries.filter((instance) => !search || [instance.agent?.name, instance.application.nodeId, instance.siteName, ...instance.realityServices.map((service) => service.displayName)].some((value) => value?.toLocaleLowerCase().includes(search))).filter((instance) => matchesEntryPurpose(instance, checkFor(instance), purpose)).sort((a, b) => compareSelection({ ready: entryAvailable(a), check: checkFor(a), name: a.agent?.name ?? a.application.nodeId }, { ready: entryAvailable(b), check: checkFor(b), name: b.agent?.name ?? b.application.nodeId }, order));
  const siteNames = Object.fromEntries(data.agents.map((agent) => [agent.id, data.sites.find((site) => site.id === agent.siteId)?.name ?? ""]));
  const controller = group.controller;
  const controllerWebIDs = new Set(controller?.services.filter((service) => service.protocol === "http" || service.protocol === "https").map((service) => service.id));
  const controllerAttention = controller?.publications.some((publication) => controllerWebIDs.has(publication.serviceId) && publicationNeedsAttention(publication));
  const accounts = manifest.pages.find((item) => item.surface === "manager")!;
  return <section aria-label="Glivela" className="apps-three-xui flex min-w-0 flex-col gap-3" data-app-workspace={manifest.appKey}>
    <LandingNotice language={language} />
    <div className="apps-three-xui-toolbar flex flex-wrap items-center gap-3">
      {page === "nodes" ? <><InputGroup className="w-full sm:w-48"><InputGroupInput type="search" value={query} onChange={(event) => setQuery(event.target.value)} aria-label={copy(language, "搜索节点", "Search nodes")} placeholder={copy(language, "搜索节点…", "Search nodes…")} /><InputGroupAddon><SearchIcon aria-hidden="true" /></InputGroupAddon></InputGroup>
      <SelectControl className="sm:w-40" aria-label={copy(language, "按用途筛选", "Filter by purpose")} value={purpose} onValueChange={setPurpose} options={[
        { value: "all", label: copy(language, "全部用途", "All uses") },
        { value: "ai", label: "ChatGPT" },
        { value: "streaming", label: copy(language, "Netflix + Disney+", "Netflix + Disney+") },
        { value: "residential", label: copy(language, "家宽出口", "Residential exits") },
      ]} />
      <SelectControl className="sm:w-40" aria-label={copy(language, "节点排序", "Node order")} value={order} onValueChange={setOrder} options={[
        { value: "quality", label: copy(language, "IP 质量优先", "IP quality first") },
        { value: "name", label: copy(language, "按名称", "By name") },
      ]} />
      {query || purpose !== "all" ? <Button variant="ghost" size="sm" onClick={() => { setQuery(""); setPurpose("all"); }}>{copy(language, "清除筛选", "Clear filters")}</Button> : null}</> : null}
      {controller ? <div className="ml-auto flex min-w-0 flex-wrap items-center gap-2">{controller.activeChange || controller.application.status !== "running" ? <ApplicationPrimaryStatus instance={controller} language={language} /> : null}{controllerAttention ? <span className="text-xs text-destructive">{copy(language, "入口待处理", "Access needs attention")}</span> : null}<div className="ml-auto flex items-center gap-2"><GlivelaUpdates group={group} language={language} onUpgrade={onUpgrade} /><Button disabled={controller.locked} size="sm" variant="secondary" onClick={() => onClients(controller.application)}>{accounts.title[language]}</Button><Button size="icon-sm" variant="ghost" aria-label={copy(language, "管理订阅主机", "Manage subscription controller")} onClick={() => onManage(controller.application)}><EllipsisIcon aria-hidden="true" /></Button></div></div> : null}
    </div>
    <Tabs value={page} onValueChange={(value) => { if (typeof value === "string") setPage(value); }}>
      <div className="glivela-view-bar"><TabsList variant="line" aria-label={copy(language, "Glivela 视图", "Glivela views")}>{manifest.pages.filter((item) => item.surface === "tab").map((item) => <TabsTrigger key={item.id} value={item.id}>{item.title[language]}</TabsTrigger>)}</TabsList><span className="text-xs text-muted-foreground">{copy(language, `共 ${entries.length} 个线路机 · ${landing?.view?.servers.length ?? "—"} 个落地机`, `Total: ${entries.length} entry nodes · ${landing?.view?.servers.length ?? "—"} landing nodes`)}</span></div>
      <TabsContent value="nodes"><div className="glivela-evidence-bar"><QualityNotice instances={instances} data={data} language={language} purpose={purpose} search={search} /><UnlockLegend language={language} /></div><div className="glivela-node-list"><Table aria-label={copy(language, "Glivela 节点", "Glivela nodes")} className="apps-instance-table glivela-comparison-table">
        <colgroup><col className="glivela-node-column" /><col className="glivela-quality-column" /><col span={nodeTableColumns - 4} className="glivela-service-column" /><col className="glivela-state-column" /><col className="glivela-actions-column" /></colgroup>
        <TableHeader><TableRow><TableHead scope="col">{copy(language, "节点", "Node")}</TableHead><TableHead scope="col" title={copy(language, "分数仅表示出口 IP 质量，不代表速度。", "Scores describe exit IP quality, not speed.")}>{copy(language, "IP 质量", "IP quality")}</TableHead><UnlockHeaders /><TableHead scope="col">{copy(language, "状态", "Status")}</TableHead><TableHead scope="col"><span className="sr-only">{copy(language, "操作", "Actions")}</span></TableHead></TableRow></TableHeader>
        <TableBody><TableRow className="glivela-node-group"><TableCell colSpan={nodeTableColumns} className="text-xs">{copy(language, "线路机", "Entry nodes")} {instances.length}</TableCell></TableRow>
          {instances.map((instance) => {
            const name = instance.agent?.name ?? instance.application.nodeId;
            const service = instance.realityServices[0];
            const state = entryState(instance);
            return <TableRow key={instance.application.id} data-application-id={instance.application.id}>
              <TableCell className="whitespace-normal"><div className="flex items-center gap-2"><RegionFlag code={service?.regionCode} language={language} /><span className="font-medium">{name}</span></div><p className="mt-1 text-xs text-muted-foreground"><NodeLocation regionCode={service?.regionCode} siteName={showSite ? instance.siteName : undefined} language={language} />{service?.protocols?.length ? ` · ${service.protocols.map((protocol) => protocol.toUpperCase()).join(" / ")}` : ""}</p></TableCell>
              <NodeQualityCells nodeId={instance.application.nodeId} name={name} language={language} address={instance.agent?.publicEgress?.address} check={checkFor(instance)} />
              <TableCell className="whitespace-normal"><div className="glivela-entry-status"><EntryStatus instance={instance} language={language} />{state === "access_error" ? <VerifyEntry instance={instance} language={language} mutate={mutate} /> : null}{state === "unconfigured" ? <Button disabled={instance.locked} variant="ghost" size="sm" onClick={() => onManage(instance.application)}>{copy(language, "配置", "Configure")}</Button> : null}</div></TableCell>
              <TableCell><DropdownMenu><DropdownMenuTrigger render={<Button aria-label={copy(language, `${name} 操作`, `${name} actions`)} size="icon-sm" variant="ghost" />}><EllipsisIcon aria-hidden="true" /></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuGroup>
                <DropdownMenuItem onClick={() => compareRoute(instance.application.nodeId, landingId)}>{copy(language, "比较线路速度", "Compare route speeds")}</DropdownMenuItem>
                <DropdownMenuItem onClick={() => onManage(instance.application)}>{copy(language, "管理应用", "Manage application")}</DropdownMenuItem>
                {instance.application.updateAvailable && !instance.activeChange ? <DropdownMenuItem disabled={!instance.agent?.connected || catalogInstallBlocked(instance.app) || ["pending", "deploying"].includes(instance.application.status)} onClick={() => onUpgrade(instance.application)}>{copy(language, "更新应用", "Update application")}</DropdownMenuItem> : null}
              </DropdownMenuGroup></DropdownMenuContent></DropdownMenu></TableCell>
            </TableRow>;
          })}
          {!instances.length ? <TableRow><TableCell colSpan={nodeTableColumns} className="py-8 text-center text-muted-foreground">{copy(language, "没有匹配的线路机", "No matching entry nodes")}</TableCell></TableRow> : null}
          <LandingTableRows language={language} search={search} purpose={purpose} order={order} siteNames={siteNames} data={data} mutate={mutate} onCompare={(nodeId) => compareRoute("", nodeId)} />
        </TableBody>
      </Table></div></TabsContent>
      <TabsContent value="traffic"><GlivelaTrafficPanel data={data} language={language} /></TabsContent>
      <TabsContent value="network"><GlivelaLinkTests instances={entries} language={language} entryId={entryId} landingId={landingId} onEntryChange={setEntryId} onLandingChange={setLandingId} /></TabsContent>
    </Tabs>
  </section>;
}

function EntryStatus({ instance, language }: { instance: InstalledAppInstance; language: AppWorkspaceProps["language"] }) {
  const state = entryState(instance);
  const labels = { ready: ["可用", "Available"], offline: ["离线", "Offline"], recovery: ["需要恢复", "Recovery required"], changing: ["配置中", "Configuring"], app_unavailable: ["应用异常", "App unavailable"], syncing: ["订阅未就绪", "Subscription not ready"], unconfigured: ["入口未配置", "Entry not configured"], access_error: ["入口异常", "Entry unavailable"] } as const;
  const error = ["offline", "recovery", "app_unavailable", "access_error"].includes(state);
  return <span className={error ? "inline-flex items-center gap-1.5 text-destructive" : "inline-flex items-center gap-1.5"}><span aria-hidden="true" className={`apps-status-dot ${state === "ready" ? "bg-latency-fast" : error ? "bg-destructive" : "bg-muted-foreground"}`} />{copy(language, labels[state][0], labels[state][1])}</span>;
}

function VerifyEntry({ instance, language, mutate }: Pick<AppWorkspaceProps, "language" | "mutate"> & { instance: InstalledAppInstance }) {
  const [busy, setBusy] = useState(false);
  const publication = instance.realityPublications.find((value) => publicationNeedsAttention(value) || value.status !== "ready" && value.status !== "stopped");
  const protocols = instance.realityServices[0]?.protocols;
  if (!publication || protocols?.includes("hy2") && !protocols.includes("vless")) return null;
  const verify = async () => {
    if (busy || instance.locked) return;
    setBusy(true);
    try { await mutate(() => api.verifyPublication(publication.id), copy(language, "入口检查已完成。", "Access point checked.")); }
    catch { /* The platform mutation notice reports failures. */ }
    finally { setBusy(false); }
  };
  return <Button disabled={busy || instance.locked || !instance.agent?.connected} size="sm" variant="ghost" onClick={() => void verify()}>{copy(language, "检查", "Check")}</Button>;
}
