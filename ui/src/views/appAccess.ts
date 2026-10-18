import type { AppData, Deployment } from "../types";
import type { Language } from "../translations";
import { copy } from "./shared";

export function senulunPrivateAccess(data: AppData) {
  const service = data.applications.find((app) => app.appKey === "vastora-official/pulse" && app.status === "running");
  const dashboard = data.services.find((value) => value.applicationId === service?.id && value.name === "dashboard" && ["ready", "publishing"].includes(value.status));
  return data.publications.find((value) => value.serviceId === dashboard?.id && value.status === "ready" && value.tlsEnabled && (value.kind === "headscale_gateway" || value.kind === "lan_gateway"));
}

export function operationLabel(language: Language, operation: Deployment["operation"]) {
  const labels: Record<Deployment["operation"], [string, string]> = { install: ["安装", "Install"], upgrade: ["升级", "Upgrade"], configure: ["修改配置", "Configure"], uninstall: ["卸载", "Uninstall"] };
  return copy(language, ...labels[operation]);
}

export function secureDashboardURL(value?: string) {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol === "https:" && url.hostname && !url.username && !url.password && !url.hash) return url.href;
  } catch { /* An incomplete access publication cannot open the dashboard. */ }
  return undefined;
}
