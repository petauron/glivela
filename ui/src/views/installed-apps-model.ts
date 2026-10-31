import type { AgentView, Application, AppView, Deployment, Publication, Service, ThreeXUIControllerMigration } from "../types";

export const threeXUIAppKey = "vastora-official/3x-ui";

export const meridianAppKey = "vastora-official/meridian";

export type InstalledAppInstance = {
  application: Application;
  controller?: Application;
  agent?: AgentView;
  siteName: string;
  app?: AppView;
  services: Service[];
  publications: Publication[];
  realityServices: Service[];
  realityPublications: Publication[];
  activeChange?: Deployment;
  deployment?: Deployment;
  locked: boolean;
};

export type InstalledAppGroup = {
  id: string;
  appKey: string;
  app?: AppView;
  controller?: InstalledAppInstance;
  convergence?: ThreeXUIControllerMigration;
  legacyControllers: InstalledAppInstance[];
  instances: InstalledAppInstance[];
};

export function publicationNeedsAttention(publication: Publication) {
  return Boolean(publication.actionRequired || publication.lastError || publication.status === "failed" || publication.status === "degraded");
}

export function serviceNeedsAttention(service: Service) {
  return Boolean(service.lastError || service.actionRequiredReason || service.guardStatus === "action_required" || service.status === "failed" || service.status === "degraded");
}

// A subscription-only controller remains in its own band, not the node table.
export function showInstalledNode(instance: InstalledAppInstance) {
  const legacyControllerOnly = instance.application.appKey === threeXUIAppKey && instance.application.role === "master"
    && instance.application.id === instance.application.controllerApplicationId && instance.realityServices.length === 0;
  const meridianControllerOnly = instance.application.appKey === meridianAppKey && instance.realityServices.length === 0
    && instance.services.some((service) => service.appProtocol === "meridian/subscription");
  return !legacyControllerOnly && !meridianControllerOnly;
}
