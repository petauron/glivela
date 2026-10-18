import type { AppData, CenterStatus } from "./types";
export function emptyAppData(status: CenterStatus): AppData {
  return {
    status,
    centerUpdate: { currentVersion: status.version, updateAvailable: false, releaseCheckAvailable: false, automatic: false, state: "idle" },
    sources: [],
    apps: [],
    registryCredentials: [],
    agents: [],
    deployments: [],
    organizations: [],
    sites: [],
    applications: [],
    services: [],
    publications: [],
    routes: [],
    integrations: [],
    actions: [],
    threeXUIControllerMigrations: [],
    meridian: { cutover: { state: "not_required", subscriptionAuthority: "meridian", expectedAccounts: 0, importedAccounts: 0, expectedCredentials: 0, importedCredentials: 0, expectedEndpoints: 0, readyEndpoints: 0, retiredEndpoints: 0, expectedRoutes: 0, readyRoutes: 0, blockedRoutes: 0, pendingDeployments: 0, failedDeployments: 0, updatedAt: "", complete: false }, endpoints: [], accounts: [], grants: [] },
    systemDomain: { namespace: "", centerUrl: status.agentConnectUrl, headscaleUrl: "", cloudflareZone: "", aliases: [], activePublications: 0, pendingCleanup: 0, builtinHeadscale: false, cloudflareOAuthAvailable: false },
    centerRemoteAccess: null
  };
}
