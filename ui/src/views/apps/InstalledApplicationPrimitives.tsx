import { ShieldAlertIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";
import type { Application } from "@/types";
import type { Language } from "@/translations";
import { operationLabel } from "../appAccess";
import { catalogInstallBlocked, copy, StateBadge } from "../shared";
import { threeXUIAppKey, type InstalledAppInstance } from "../installed-apps-model";

export function ApplicationUpdate({ instance, language, onUpgrade }: { instance: InstalledAppInstance; language: Language; onUpgrade: (application: Application) => void }) {
  const { application, app, agent, activeChange } = instance;
  if (!application.updateAvailable || activeChange) return null;
  const legacy = application.appKey === threeXUIAppKey && application.role === "master" && Boolean(application.controllerApplicationId) && application.id !== application.controllerApplicationId;
  const disabled = !agent?.connected || legacy || catalogInstallBlocked(app) || ["pending", "deploying"].includes(application.status);
  const adoptionRequired = application.adoptionState === "pending" || application.adoptionState === "blocked";
  const name = agent?.name ?? application.nodeId;
  return <Button aria-label={copy(language, `更新 ${name} 的应用`, `Update application on ${name}`)} className="max-md:min-h-11" disabled={disabled} onClick={() => onUpgrade(application)} size="sm" variant="outline" title={copy(language, `更新到 v${application.availableVersion}`, `Update to v${application.availableVersion}`)}>
    {adoptionRequired ? copy(language, "处理更新", "Resolve update") : application.status === "failed" ? copy(language, "重试更新", "Retry update") : copy(language, "更新", "Update")}
  </Button>;
}

export function ApplicationPrimaryStatus({ instance, language }: { instance: InstalledAppInstance; language: Language }) {
  const { application, activeChange } = instance;
  if (activeChange) return <Badge role="status" variant={activeChange.reconciliationRequired ? "destructive" : "outline"}>
    {activeChange.reconciliationRequired ? <ShieldAlertIcon aria-hidden="true" data-icon="inline-start" /> : <Spinner aria-hidden="true" data-icon="inline-start" className="motion-reduce:animate-none" />}
    {activeChange.reconciliationRequired ? copy(language, "需要恢复", "Recovery required")
      : activeChange.operation === "upgrade" ? copy(language, "正在更新", "Updating")
      : copy(language, `正在${operationLabel(language, activeChange.operation)}`, `${operationLabel(language, activeChange.operation)} in progress`)}
  </Badge>;
  return application.status === "running"
    ? <span className={cn("inline-flex items-center gap-2", application.appKey === threeXUIAppKey && "text-muted-foreground")}><span aria-hidden="true" className="apps-status-dot bg-latency-fast" />{copy(language, "运行中", "Running")}</span>
    : <StateBadge language={language} value={application.status} />;
}
