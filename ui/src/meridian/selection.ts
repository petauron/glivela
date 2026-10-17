import type { IPQualityCheck } from "@/ip-quality-types";
import { publicationNeedsAttention, serviceNeedsAttention } from "@/views/installed-apps-model";
import type { InstalledAppInstance } from "@/views/installed-apps-model";

export function usableReport(check?: IPQualityCheck) {
  return Boolean(check?.state === "succeeded" && check.report && !check.error && !check.stale && check.assessment?.status !== "ip_changed");
}

export function historicalReport(check?: IPQualityCheck) {
  const checkedAt = Date.parse(check?.checkedAt ?? "");
  return check?.assessment?.status === "expired" || !Number.isFinite(checkedAt) || Date.now() - checkedAt > 24 * 60 * 60 * 1000;
}

export function matchesPurpose(check: IPQualityCheck | undefined, purpose: string) {
  if (purpose === "all") return true;
  if (!usableReport(check)) return false;
  if (purpose === "residential") return check?.assessment?.ipType === "residential";
  const services = purpose === "streaming" ? ["Netflix", "DisneyPlus"] : ["ChatGPT"];
  return services.every((name) => check?.report?.services.some((service) => service.name === name && service.status.trim().toLowerCase() === "yes"));
}

export function entryState(instance: InstalledAppInstance) {
  if (!instance.agent?.connected || instance.agent.status !== "active" || instance.agent.credentialRevoked) return "offline";
  if (instance.activeChange?.reconciliationRequired) return "recovery";
  if (instance.activeChange) return "changing";
  if (instance.application.status !== "running") return "app_unavailable";
  if (instance.application.role === "worker" && (!instance.controller || instance.application.nodeSyncStatus !== "ready")) return "syncing";
  const service = instance.realityServices[0];
  if (!service) return "unconfigured";
  if (instance.realityServices.some(serviceNeedsAttention) || instance.realityPublications.some(publicationNeedsAttention)) return "access_error";
  if (instance.realityServices.some((value) => value.guardStatus === "pending" || value.guardStatus === "hardening") || instance.realityPublications.some((value) => value.status === "pending" || value.status === "applying")) return "changing";
  const hy2Only = service?.protocols?.includes("hy2") && !service.protocols.includes("vless");
  return hy2Only || instance.realityPublications.some((publication) => publication.status === "ready") ? "ready" : "unconfigured";
}

export function entryAvailable(instance: InstalledAppInstance) {
  return entryState(instance) === "ready";
}

export function matchesEntryPurpose(instance: InstalledAppInstance, check: IPQualityCheck | undefined, purpose: string) {
  return purpose === "all" || entryAvailable(instance) && matchesPurpose(check, purpose);
}

// Keep unavailable nodes last; quality order follows scores, not report age.
export function compareSelection(a: { ready: boolean; check?: IPQualityCheck; name: string }, b: { ready: boolean; check?: IPQualityCheck; name: string }, order: string) {
  if (a.ready !== b.ready) return a.ready ? -1 : 1;
  if (order === "quality") {
    const score = (check?: IPQualityCheck) => usableReport(check) ? (check?.assessment?.status === "partial" ? -1 : check?.assessment?.score ?? -1) : -1;
    const differenceScore = score(b.check) - score(a.check);
    if (differenceScore) return differenceScore;
  }
  return a.name.localeCompare(b.name);
}
