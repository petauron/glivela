import { useEffect, useState } from "react";
import { ExternalLinkIcon, RefreshCwIcon } from "lucide-react";
import { api } from "@/api";
import type { AppData } from "@/host-contract";
import type { MeridianTraffic } from "@/meridian-types";
import type { Language } from "@/translations";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { senulunPrivateAccess, secureDashboardURL } from "@/views/appAccess";
import { copy, userError } from "@/views/shared";

function bytes(value: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const index = value > 0 ? Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1) : 0;
  return `${(value / 1024 ** index).toLocaleString(undefined, { maximumFractionDigits: index ? 2 : 0 })} ${units[index]}`;
}

export function GlivelaTrafficPanel({ data, language }: { data: AppData; language: Language }) {
  const [traffic, setTraffic] = useState<MeridianTraffic | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setBusy(true); setError(""); setTraffic(null);
    void api.meridianTraffic(controller.signal).then((value) => {
      if (!controller.signal.aborted) setTraffic(value);
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(userError(language, cause));
    }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [revision, language]);
  const publication = senulunPrivateAccess(data);
  const senulunURL = publication && !publication.actionRequired && !publication.lastError ? secureDashboardURL(publication.accessUrl) : undefined;
  const labels = {
    current: copy(language, "最近采样", "Recent sample"), missing: copy(language, "待采集", "Not sampled"),
    partial: copy(language, "部分凭据未采集", "Some credentials not sampled"), stale: copy(language, "历史用量", "Historical usage"),
  };
  const date = (value?: string) => value ? new Date(value).toLocaleString(language) : "—";
  return <section className="flex min-w-0 flex-col gap-3" aria-label={copy(language, "流量用量", "Traffic usage")}>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="text-xs text-muted-foreground">{copy(language, "按线路合计所有账号 · 上传 / 下载以客户端为准", "All accounts per route · upload / download from the client perspective")}</p>
      <Button size="sm" variant="outline" disabled={busy} onClick={() => setRevision((value) => value + 1)}><RefreshCwIcon />{copy(language, "刷新用量", "Refresh usage")}</Button>
    </div>
    {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
    {busy ? <p role="status" className="text-sm text-muted-foreground">{copy(language, "正在读取用量…", "Reading usage…")}</p> : null}
    {traffic ? <div className="overflow-hidden rounded-xl border"><Table aria-label={copy(language, "线路流量", "Route traffic")}>
      <TableHeader><TableRow><TableHead>{copy(language, "线路", "Route")}</TableHead><TableHead className="text-right">{copy(language, "上传", "Upload")}</TableHead><TableHead className="text-right">{copy(language, "下载", "Download")}</TableHead><TableHead className="text-right">{copy(language, "合计", "Total")}</TableHead><TableHead>{copy(language, "采样状态", "Sampling")}</TableHead></TableRow></TableHeader>
      <TableBody>{traffic.lines.map((line) => <TableRow key={`${line.entryNodeId}/${line.egressNodeId ?? "native"}`}>
        <TableCell className="whitespace-normal"><span className="font-medium">{line.entryName} → {line.egressName || copy(language, "原生出口", "Native exit")}</span><details className="mt-1 text-xs text-muted-foreground"><summary className="cursor-pointer">{copy(language, "统计范围", "Coverage")}</summary><p>{copy(language, "从以下时间开始累计（非月度账单）", "Cumulative since tracking began (not a monthly bill)")}：{date(line.startedAt)}</p><p>{copy(language, "已采集凭据", "Tracked credentials")}：{line.trackedCredentials}/{line.credentialCount}</p><p>{copy(language, "不包含采集前或采集缺口中的流量。", "Traffic before tracking or lost during reporting gaps is not reconstructed.")}</p></details></TableCell>
        <TableCell className="text-right tabular-nums">{line.state === "missing" ? "—" : bytes(line.uploadBytes)}</TableCell>
        <TableCell className="text-right tabular-nums">{line.state === "missing" ? "—" : bytes(line.downloadBytes)}</TableCell>
        <TableCell className="text-right font-medium tabular-nums">{line.state === "missing" ? "—" : bytes(line.totalBytes)}</TableCell>
        <TableCell className="whitespace-normal text-xs text-muted-foreground"><span>{labels[line.state]}</span><time className="mt-1 block" dateTime={line.observedAt}>{date(line.observedAt)}</time></TableCell>
      </TableRow>)}{!traffic.lines.length ? <TableRow><TableCell colSpan={5} className="py-6 text-center text-muted-foreground">{copy(language, "暂无订阅线路", "No subscription routes")}</TableCell></TableRow> : null}</TableBody>
    </Table></div> : null}
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border p-4">
      <div className="min-w-0 flex-1"><h3 className="text-sm font-medium">{copy(language, "服务器套餐 · Senulun", "Server traffic budgets · Senulun")}</h3><p className="mt-1 text-xs text-muted-foreground">{copy(language, "查看主机已用 / 剩余流量，设置额度、UTC 月度重置日（1–28）及双向 / 仅出站计费。阈值提醒不自动停用线路。", "View host used / remaining traffic; configure budget, monthly UTC reset day (1–28), and total / outbound counting. Threshold alerts do not disable routes.")}</p><p className="mt-1 text-xs text-muted-foreground">{copy(language, "主机计量包含其他应用及传输开销，与线路业务用量分开统计；供应商账单为准。", "Host monitoring includes other applications and transport overhead, separately from route usage; provider billing remains authoritative.")}</p></div>
      {senulunURL ? <Button size="sm" variant="outline" nativeButton={false} render={<a href={senulunURL} rel="noreferrer" target="_blank" />}><ExternalLinkIcon />{copy(language, "查看 / 设置服务器流量", "View / configure server traffic")}</Button> : <span role="status" className="text-xs text-muted-foreground">{copy(language, "Senulun 入口不可用，请先配置监控访问。", "Senulun access is unavailable; configure monitoring access first.")}</span>}
    </div>
  </section>;
}
