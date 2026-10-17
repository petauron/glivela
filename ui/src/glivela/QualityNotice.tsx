import { useState } from "react";
import type { AppData } from "@/App";
import type { Language } from "@/translations";
import type { InstalledAppInstance } from "@/views/installed-apps-model";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { IPQualityButton, useIPQuality } from "@/views/IPQuality";
import { ipQualityCheckForAddress, landingQualityAddress } from "@/views/ipQualityModel";
import { useLanding } from "@/views/LandingControls";
import { copy } from "@/views/shared";
import { historicalReport, matchesPurpose, usableReport } from "./selection";

export function QualityNotice({ instances, data, language, purpose, search }: { instances: InstalledAppInstance[]; data: AppData; language: Language; purpose: string; search: string }) {
  const quality = useIPQuality();
  const landing = useLanding();
  const [open, setOpen] = useState(false);
  const nodes = [
    ...instances.map((instance) => ({ id: instance.application.nodeId, name: instance.agent?.name ?? instance.application.nodeId, address: instance.agent?.publicEgress?.address ?? "", landing: false })),
    ...(landing?.view?.servers ?? []).filter((server) => purpose === "all" || server.status === "ready").map((server) => ({ id: server.nodeId, name: server.name, address: landingQualityAddress(server.egressIp ?? "", data.agents.find((agent) => agent.id === server.nodeId)?.publicEgress, (quality?.targets ?? []).filter((target) => target.agentId === server.nodeId)), landing: true })),
  ].map((node) => ({ ...node, check: quality?.error ? undefined : ipQualityCheckForAddress(quality?.checks ?? [], node.id, node.address) }))
    .filter((node) => (!search || node.name.toLocaleLowerCase().includes(search) || node.id.toLocaleLowerCase().includes(search)) && matchesPurpose(node.check, purpose));
  const historical = nodes.filter((node) => usableReport(node.check) && historicalReport(node.check));
  const missing = nodes.filter((node) => !usableReport(node.check));
  const recheck = [...historical, ...missing];
  return <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-muted-foreground">
    <span>{quality?.error ? copy(language, "检测数据读取失败", "Could not load checks") : historical.length ? copy(language, `${historical.length} 个${purpose === "all" ? "历史结果" : "历史匹配"} · 建议复测`, `${historical.length} historical ${purpose === "all" ? "results" : "matches"} · Recheck recommended`) : copy(language, "解锁以最近检测为准", "Availability reflects the latest checks")}{missing.length && !quality?.error ? copy(language, ` · ${missing.length} 个待检测`, ` · ${missing.length} unchecked`) : ""}</span>
    {recheck.length ? <Sheet open={open} onOpenChange={setOpen}>
      <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>{copy(language, "复测", "Recheck")}</Button>
      <SheetContent className="apps-workspace"><SheetHeader><SheetTitle>{copy(language, "更新 IP 检测", "Refresh IP checks")}</SheetTitle><SheetDescription>{copy(language, "选择节点查看检测详情并重新检测。历史分数继续保留。", "Choose a node to inspect and recheck it. Historical scores remain visible.")}</SheetDescription></SheetHeader>
        <div className="flex flex-col overflow-y-auto px-4">{recheck.map((node) => <div key={`${node.id}:${node.address}`} className="flex items-center justify-between gap-3 border-b py-3"><div><p>{node.name}</p><p className="text-xs text-muted-foreground">{usableReport(node.check) ? copy(language, "历史检测", "Historical check") : copy(language, "待检测", "Unchecked")}</p></div><IPQualityButton nodeId={node.id} name={node.name} language={language} egressAddress={node.address} landingEgress={node.landing} compact /></div>)}</div>
      </SheetContent>
    </Sheet> : null}
  </div>;
}

export function UnlockLegend({ language }: { language: Language }) {
  const [open, setOpen] = useState(false);
  return <Sheet open={open} onOpenChange={setOpen}>
    <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>{copy(language, "状态说明", "Status guide")}</Button>
    <SheetContent className="apps-workspace"><SheetHeader><SheetTitle>{copy(language, "解锁状态", "Service availability")}</SheetTitle><SheetDescription>{copy(language, "点击表格里的状态可查看该项的地区与检测时间。", "Click any service status for its region and check time.")}</SheetDescription></SheetHeader>
      <dl className="grid grid-cols-[auto_1fr] gap-x-5 gap-y-4 px-4 text-sm">
        <dt className="text-latency-fast">✓</dt><dd>{copy(language, "已解锁，地区与出口一致", "Unlocked in the exit region")}</dd>
        <dt className="text-latency-medium">US / CA</dt><dd>{copy(language, "已解锁，但与出口地区不同", "Unlocked in a different region")}</dd>
        <dt>✓?</dt><dd>{copy(language, "已解锁，地区未知", "Unlocked; region unknown")}</dd>
        <dt className="text-destructive">×</dt><dd>{copy(language, "未解锁", "Blocked")}</dd>
        <dt className="text-latency-medium">{copy(language, "受限", "Limited")}</dt><dd>{copy(language, "部分可用，如仅 App 或仅自制内容", "Partial access, such as app-only or originals-only")}</dd>
        <dt>{copy(language, "失败", "Error")}</dt><dd>{copy(language, "检测失败，不代表未解锁", "The check failed; availability is unknown")}</dd>
        <dt>—</dt><dd>{copy(language, "未取得结果", "No result available")}</dd>
      </dl>
    </SheetContent>
  </Sheet>;
}
