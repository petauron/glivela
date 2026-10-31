import type { IPQualityAssessment, IPQualityReport, IPQualityService } from "../ip-quality-types";
import { cleanIPQualityValue } from "../views/ipQualityModel";

export type QualityTarget = { available: boolean; nodeId: string; runtimeId: string; address: string };
export type QualityCheck = { nodeId: string; address: string; id: string; state: string; error?: string; report?: IPQualityReport; assessment: IPQualityAssessment; checkedAt?: string; historical: boolean };
export type QualityResults = { targets: QualityTarget[]; checks: QualityCheck[] };
export type QualityRecord = { target?: QualityTarget; check?: QualityCheck; nodeId: string; address: string };
export const qualityStates: Record<string, string> = { pending: "等待节点领取", running: "检测中", succeeded: "已有结果", failed: "检测失败" };
export const qualityCategories = [
  { id: "streaming", label: "流媒体", services: [{ name: "Netflix", label: "Netflix" }, { name: "DisneyPlus", label: "Disney+" }, { name: "Youtube", label: "YouTube" }, { name: "AmazonPrimeVideo", label: "Prime Video" }] },
  { id: "ai", label: "AI", services: [{ name: "ChatGPT", label: "ChatGPT" }] },
  { id: "other", label: "其他", services: [{ name: "TikTok", label: "TikTok" }, { name: "Reddit", label: "Reddit" }] },
] as const;

export function qualityRecords(results?: QualityResults): QualityRecord[] {
  if (!results) return [];
  const key = (nodeId: string, address: string) => `${nodeId}/${address}`;
  const checks = new Map(results.checks.map(check => [key(check.nodeId, check.address), check]));
  const targets = new Set(results.targets.map(target => key(target.nodeId, target.address)));
  return [
    ...results.targets.map(target => ({ target, check: checks.get(key(target.nodeId, target.address)), nodeId: target.nodeId, address: target.address })),
    ...results.checks.filter(check => !targets.has(key(check.nodeId, check.address))).map(check => ({ check, nodeId: check.nodeId, address: check.address })),
  ];
}

export function serviceResult(service?: IPQualityService) {
  const status = cleanIPQualityValue(service?.status).toLowerCase();
  if (status === "yes") return { label: "已解锁", tone: "good", unlocked: true };
  if (["org", "originals only", "nf.only"].includes(status)) return { label: "仅自制", tone: "warning", unlocked: false };
  if (["apponly", "webonly"].includes(status)) return { label: status === "apponly" ? "仅 APP" : "仅网页", tone: "warning", unlocked: false };
  if (["no", "block"].includes(status)) return { label: "未解锁", tone: "bad", unlocked: false };
  if (["failed", "fail", "error"].includes(status)) return { label: "检测失败", tone: "muted", unlocked: false };
  if (["", "null", "pending"].includes(status)) return { label: "待确认", tone: "muted", unlocked: false };
  // Keep unfamiliar provider results visible without inferring success or a ban.
  return { label: cleanIPQualityValue(service?.status), tone: "muted", unlocked: false };
}

export function unlockSummary(report?: IPQualityReport) {
  const count = qualityCategories.reduce((sum, category) => sum + category.services.filter(meta => serviceResult(report?.services.find(service => service.name === meta.name)).unlocked).length, 0);
  const total = qualityCategories.reduce((sum, category) => sum + category.services.length, 0);
  return { count, total, label: !report ? "未检测" : count === total ? "全部解锁" : count > 0 ? "部分解锁" : "尚无确认解锁" };
}

export function qualityHistory(record: QualityRecord) {
  const check = record.check;
  return !!check?.report && (!record.target || check.historical || check.state !== "succeeded" || check.assessment.status === "expired" || check.assessment.status === "ip_changed");
}
