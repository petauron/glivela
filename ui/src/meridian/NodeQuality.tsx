import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { IPQualityCheck } from "@/ip-quality-types";
import { TableCell, TableHead } from "@/components/ui/table";
import type { Language } from "@/translations";
import { AssessmentBadge, AssessmentSummary, AssessmentTypeBadge } from "@/views/IPAssessment";
import { IPQualityButton } from "@/views/IPQuality";
import { cleanIPQualityValue, unlockLabel, unlockServiceLabel, unlockServices } from "@/views/ipQualityModel";
import { copy } from "@/views/shared";
import { historicalReport, usableReport } from "./selection";

export const nodeTableColumns = 4 + unlockServices.length;

export function UnlockHeaders() {
  return <>{unlockServices.map((name) => <TableHead key={name} scope="col" className="meridian-service-cell" title={unlockServiceLabel(name)}>{name === "ChatGPT" || name === "AmazonPrimeVideo" ? unlockServiceLabel(name, true) : unlockServiceLabel(name)}</TableHead>)}</>;
}

export function NodeQualityCells({ nodeId, name, address, check, language, landing = false }: {
  nodeId: string; name: string; address?: string; check?: IPQualityCheck; language: Language; landing?: boolean;
}) {
  const [detail, setDetail] = useState<{ title: string; description: string } | null>(null);
  const [scoreOpen, setScoreOpen] = useState(false);
  const usable = usableReport(check);
  const assessment = usable ? check?.assessment : undefined;
  const historical = usable && historicalReport(check);
  const date = check?.checkedAt ? new Date(check.checkedAt) : undefined;
  const dateLabel = date && Number.isFinite(date.getTime()) ? date.toLocaleDateString(language, { month: "numeric", day: "numeric" }) : "";
  const measuredAddress = address || check?.report?.address || check?.address;
  const family = measuredAddress ? measuredAddress.includes(":") ? "IPv6" : "IPv4" : "IP";
  const descriptionDate = historical ? copy(language, `历史检测 ${dateLabel} · 建议复测`, `Historical ${dateLabel} · Recheck`) : usable ? copy(language, `检测 ${dateLabel}`, `Checked ${dateLabel}`) : copy(language, "尚无有效检测", "No valid check");
  return <>
    <TableCell className="meridian-quality-cell">
      <div className="meridian-quality-score">
        <Button className="meridian-score-button" variant="ghost" size="sm" aria-label={copy(language, `${name} · 查看 IP 评分说明`, `${name} · Explain IP score`)} onClick={() => setScoreOpen(true)}><AssessmentBadge language={language} assessment={assessment} /></Button>
        <AssessmentTypeBadge language={language} assessment={assessment} checkedAt={check?.checkedAt} />
        <IPQualityButton nodeId={nodeId} name={name} language={language} egressAddress={address} landingEgress={landing} compact />
      </div>
      <div className="meridian-quality-meta text-muted-foreground" title={descriptionDate}>
        {family} · {usable ? <>{historical ? <span className="meridian-history-label">{copy(language, "历史", "Past")}</span> : null} {dateLabel}</> : copy(language, "待检测", "Pending")}
      </div>
      {landing && address?.includes(":") ? <div className="meridian-quality-meta text-muted-foreground" title={copy(language, "此出口只能打开支持 IPv6 的网站。", "This exit can only reach websites that support IPv6.")}>{copy(language, "仅 IPv6 网站", "IPv6 sites only")}</div> : null}
    </TableCell>
    {unlockServices.map((serviceName) => {
        const service = usable ? check?.report?.services.find((item) => item.name === serviceName) : undefined;
        const status = cleanIPQualityValue(service?.status).toLowerCase();
        const region = cleanIPQualityValue(service?.regionCode).toUpperCase();
        const exit = cleanIPQualityValue(check?.report?.regionCode).toUpperCase();
        const known = (value: string) => /^[A-Z]{2}$/.test(value) && !["XX", "ZZ", "UN"].includes(value);
        const yes = status === "yes";
        const mismatch = yes && known(region) && known(exit) && region !== exit;
        const matched = yes && known(region) && known(exit) && region === exit;
        const blocked = ["no", "block"].includes(status);
        const limited = ["org", "originals only", "nf.only", "apponly", "webonly", "noprem."].includes(status);
        const label = unlockLabel(language, service?.status);
        const mark = matched ? "✓" : mismatch ? region : yes ? "✓?" : blocked ? "×" : limited ? copy(language, "受限", "Limited") : ["fail", "failed", "error"].includes(status) ? copy(language, "失败", "Error") : "—";
        const description = [unlockServiceLabel(serviceName), label, yes && !known(region) ? copy(language, "解锁地区未知", "Unlock region unknown") : region, mismatch ? copy(language, "与出口地区不同", "Different from exit region") : "", historical ? copy(language, "历史检测", "Historical result") : "", date && Number.isFinite(date.getTime()) ? date.toLocaleString(language) : copy(language, "尚无检测时间", "No check time")].filter(Boolean).join(" · ");
        return <TableCell key={serviceName} className="meridian-service-cell">
          <Button variant="ghost" size="sm" className="meridian-unlock-status" title={description} aria-label={`${name} · ${description}`} onClick={() => setDetail({ title: unlockServiceLabel(serviceName), description })}><span className={matched ? "text-latency-fast" : mismatch || limited ? "text-latency-medium" : blocked ? "text-destructive" : "text-muted-foreground"}>{mark}</span></Button>
        </TableCell>;
    })}
    <Sheet open={detail !== null} onOpenChange={(open) => { if (!open) setDetail(null); }}><SheetContent className="apps-workspace"><SheetHeader><SheetTitle>{name} · {detail?.title}</SheetTitle><SheetDescription>{detail?.description}</SheetDescription></SheetHeader><div className="flex items-center gap-2 px-4"><span className="text-sm">{copy(language, "完整检测与复测", "Full report and recheck")}</span><IPQualityButton nodeId={nodeId} name={name} language={language} egressAddress={address} landingEgress={landing} compact /></div></SheetContent></Sheet>
    <Sheet open={scoreOpen} onOpenChange={setScoreOpen}><SheetContent className="apps-workspace"><SheetHeader><SheetTitle>{name} · {copy(language, "IP 评分", "IP score")}</SheetTitle><SheetDescription>{copy(language, "分数越高，出口越适合使用 AI 和流媒体；速度请看「线路测速」。", "Higher scores indicate better suitability for AI and streaming. Check Route speed for performance.")}</SheetDescription></SheetHeader><div className="flex min-h-0 flex-col gap-4 overflow-y-auto px-4 pb-4">
      <p className="text-sm text-muted-foreground">{descriptionDate}{historical ? copy(language, "。表格中的分数和解锁状态均为当时结果，不代表现在仍可用。", ". Scores and service results describe that check, not current availability.") : ""}</p>
      <AssessmentSummary language={language} assessment={assessment} report={check?.report} checkedAt={check?.checkedAt} />
      <div className="flex items-center justify-between gap-2 border-t pt-3"><span className="text-sm">{copy(language, "查看完整检测或重新检测", "View the full report or recheck")}</span><IPQualityButton nodeId={nodeId} name={name} language={language} egressAddress={address} landingEgress={landing} compact /></div>
    </div></SheetContent></Sheet>
  </>;
}
