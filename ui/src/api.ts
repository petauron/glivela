import type { ApplicationCommand, Publication, Region, RegionSuggestion } from "./types";
import type { LandingView } from "./landing-types";
import type { IPQualityPreferences, IPQualityResponse } from "./ip-quality-types";
import type { NodeDiagnosticCheck } from "./node-diagnostics-types";
import type { MeridianTraffic, MeridianAccountCreated, MeridianAccountInput, MeridianAccount, MeridianEndpoint, MeridianInventory, MeridianRouteGrant, MeridianSourceRecovery } from "./meridian-types";

export class APIError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code = "request_failed",
    readonly captchaRequired = false
  ) {
    super(message);
  }
}

function csrfToken(): string {
  return document.cookie
    .split("; ")
    .find((value) => value.startsWith("vastora_csrf="))
    ?.split("=")[1] ?? "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRF-Token", csrfToken());
  }
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const body = (await response.json().catch(() => ({}))) as T & { error?: string; code?: string; captchaRequired?: boolean };
  if (!response.ok) {
    throw new APIError(body.error ?? "Request failed", response.status, body.code, body.captchaRequired);
  }
  return body;
}

export const api = {
  ipQuality: (signal?: AbortSignal, preferences?: IPQualityPreferences, compareNodeId?: string, compareAddress?: string) => {
    const params = new URLSearchParams();
    if (preferences) { params.set("required", preferences.requiredServices.join(",")); params.set("region", preferences.targetRegion); }
    if (compareNodeId) params.set("compareNodeId", compareNodeId);
    if (compareAddress) params.set("compareAddress", compareAddress);
    return request<IPQualityResponse>(`/api/v1/ip-quality${params.size ? `?${params}` : ""}`, { signal });
  },
  checkIPQuality: (id: string, address: string, signal?: AbortSignal) => request<{ queued: boolean }>(`/api/v1/agents/${encodeURIComponent(id)}/ip-quality`, { method: "POST", body: JSON.stringify({ address }), signal }),
  nodeDiagnostics: (signal?: AbortSignal) => request<{ checks: NodeDiagnosticCheck[] }>("/api/v1/node-diagnostics", { signal }),
  checkNodeDiagnostic: (id: string, kind: NodeDiagnosticCheck["kind"], signal?: AbortSignal) => request<{ queued: boolean }>(`/api/v1/agents/${encodeURIComponent(id)}/node-diagnostics/${encodeURIComponent(kind)}`, { method: "POST", body: "{}", signal }),
  checkMeridianLinkBandwidth: (sourceNodeId: string, landingNodeId: string, signal?: AbortSignal) => request<{ queued: boolean }>("/api/v1/meridian/link-bandwidth", { method: "POST", body: JSON.stringify({ sourceNodeId, landingNodeId }), signal }),
  landing: (signal?: AbortSignal) => request<LandingView>("/api/v1/meridian/landing", { signal }),
  setLandingEgress: (nodeId: string, revision: number, egressIp: string, signal?: AbortSignal) => request<LandingView>(`/api/v1/meridian/landing/${encodeURIComponent(nodeId)}/egress`, { method: "PUT", body: JSON.stringify({ revision, egressIp }), signal }),
  selectLanding: (nodeIds: string[], revision: number, landingRegionCodes: Record<string, string>, signal?: AbortSignal, landingNameSuffixes?: Record<string, string>) => request<LandingView>("/api/v1/meridian/landing", {
    method: "PUT", body: JSON.stringify({ nodeIds, revision, landingRegionCodes, landingNameSuffixes }), signal
  }),
  meridianTraffic: (signal?: AbortSignal) => request<MeridianTraffic>("/api/v1/meridian/traffic", { signal }),
  startMeridianCutover: () => request<MeridianInventory["cutover"]>("/api/v1/meridian/cutover", { method: "POST", body: "{}" }),
  createMeridianEndpoint: (input: { applicationId: string; verificationId: string; targetIp: string; advertiseHost?: string; targetHost: string; serverName: string; fingerprint?: string; regionCode: string; name: string }) => request<MeridianEndpoint>("/api/v1/meridian/endpoints", { method: "POST", body: JSON.stringify(input) }),
  updateMeridianEndpointName: (id: string, input: { regionCode: string; name: string }) => request<MeridianEndpoint>(`/api/v1/meridian/endpoints/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(input) }),
  recoverMeridianEndpoint: (id: string) => request<{ queued: boolean }>(`/api/v1/meridian/endpoints/${encodeURIComponent(id)}/recover`, { method: "POST", body: JSON.stringify({ confirmCenterAuthority: true, executionStopped: true }) }),
  meridianSourceRecovery: (id: string) => request<MeridianSourceRecovery>(`/api/v1/meridian/endpoints/${encodeURIComponent(id)}/source-recovery`),
  recoverMeridianSource: (id: string, evidence: MeridianSourceRecovery) => request<{ queued: boolean }>(`/api/v1/meridian/endpoints/${encodeURIComponent(id)}/source-recovery`, { method: "POST", body: JSON.stringify({ previousFingerprint: evidence.previousFingerprint, currentFingerprint: evidence.currentFingerprint, endpointRevision: evidence.endpointRevision, confirmReplacement: true, executionStopped: true }) }),
  createMeridianAccount: (input: MeridianAccountInput) => request<MeridianAccountCreated>("/api/v1/meridian/accounts", { method: "POST", body: JSON.stringify(input) }),
  updateMeridianAccount: (id: string, input: Required<MeridianAccountInput>) => request<MeridianAccount>(`/api/v1/meridian/accounts/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(input) }),
  createMeridianRoute: (input: { accountId: string; endpointId: string; egressNodeId: string; ipv4EgressNodeId?: string; hideNative: boolean }) => request<MeridianRouteGrant>("/api/v1/meridian/routes", { method: "POST", body: JSON.stringify(input) }),
  revokeMeridianRoute: (id: string) => request<{ accepted: boolean }>(`/api/v1/meridian/routes/${encodeURIComponent(id)}`, { method: "DELETE", body: "{}" }),
  regions: () => request<{ regions: Region[] }>("/api/v1/regions"),
  agentRegionSuggestion: (agentId: string, signal?: AbortSignal) => request<RegionSuggestion>(`/api/v1/agents/${encodeURIComponent(agentId)}/region-suggestion`, { signal }),
  verifyRealityTarget: (applicationId: string, targetHost: string, serverName: string) => request<ApplicationCommand>(`/api/v1/applications/${encodeURIComponent(applicationId)}/reality-targets/verify`, { method: "POST", body: JSON.stringify({ targetHost, serverName }) }),
  applicationCommand: (id: string) => request<ApplicationCommand>(`/api/v1/application-commands/${encodeURIComponent(id)}`),
  verifyPublication: (id: string) => request<Publication>(`/api/v1/publications/${encodeURIComponent(id)}/verify`, { method: "POST", body: "{}" })
};
