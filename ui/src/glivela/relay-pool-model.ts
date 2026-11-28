import { latencyKey, type RouteLatency } from "./RouteLatency";
import { isSuspensionActive } from "./control-format";
import type {
  EntryObservatoryPathView,
  EntryRelayConfig,
  Inventory,
  ObservatoryConfig,
  RelayPoolMember,
  RelayPoolMemberView,
  RelayPoolStrategy,
  RelayPoolView,
  Route,
  Runtime,
  SocketCutoverPlan,
} from "./control-types";

export const RELAY_POOL_PORT = 24000;
export const MAX_IDENTIFIER_LENGTH = 128;
export const MAX_DISPLAY_NAME_RUNES = 512;
export const MAX_DRAIN_REASON_RUNES = 128;
export const MIN_OBSERVATORY_INTERVAL_SEC = 10;
export const MAX_OBSERVATORY_INTERVAL_SEC = 300;
export const DEFAULT_OBSERVATORY_CONFIG: ObservatoryConfig = {
  destination: "https://www.gstatic.com/generate_204",
  intervalSec: 10,
  sampling: 3,
  timeoutSec: 5,
};
export const DEFAULT_POOL_STRATEGY: RelayPoolStrategy = {
  expected: 1,
  maxRttMs: 500,
  tolerance: 0.05,
};

export type ObservatorySampleState = "healthy" | "unhealthy" | "stale" | "no-sample";

export type EvaluatedObservatorySample = {
  state: ObservatorySampleState;
  stale: boolean;
  delayMs?: number;
  averageMs?: number;
  minMs?: number;
  maxMs?: number;
  allSamples: number;
  failedSamples: number;
  lastErrorReason?: string;
  sampledAt?: string;
  ageMs?: number;
  outboundTag?: string;
};

export type FullPathStatus = {
  id: string;
  route: Route;
  entryId: string;
  poolId: string;
  relayNodeId: string;
  egressId: string;
  memberOrder: number;
  // Layer 1: Desired configuration
  desiredRouteEnabled: boolean;
  memberDrained: boolean;
  drainReason?: string;
  drainResumeAt?: string;
  nodeSuspended: boolean;
  // Layer 2: Control-plane admission & node applied receipts
  admitted: boolean;
  entryRuntimeReady: boolean;
  relayRuntimeReady: boolean;
  landingRuntimeReady: boolean;
  entryDesiredRev: string;
  entryAppliedRev: string;
  relayDesiredRev: string;
  relayAppliedRev: string;
  landingDesiredRev: string;
  landingAppliedRev: string;
  // Layer 3: Low-frequency Observatory telemetry sample
  telemetry: EvaluatedObservatorySample;
};

export type PooledRouteSummary = {
  route: Route;
  pool?: RelayPoolView;
  paths: FullPathStatus[];
  admittedCount: number;
  totalMembers: number;
  healthyCount: number;
  unhealthyCount: number;
  staleCount: number;
  noSampleCount: number;
  bestDelayMs?: number;
  blockedByEmptyPool: boolean;
};

export type RouteTopologyKind = "pooled" | "legacy-three-hop" | "two-hop";

export type TopologyFilter = "all" | "pooled" | "two-hop" | "attention";

export type TopologySelection =
  | { kind: "entry"; id: string }
  | { kind: "pool"; id: string }
  | { kind: "member"; poolId: string; nodeId: string }
  | { kind: "legacy-relay"; id: string }
  | { kind: "legacy-route"; id: string }
  | { kind: "landing"; id: string }
  | { kind: "two-hop"; id: string }
  | { kind: "path"; id: string }
  | null;

export type TopologyEntryNode = {
  id: string;
  name: string;
  x: number;
  y: number;
  width: number;
  height: number;
  runtime?: Runtime;
  suspended: boolean;
  relayConfig?: EntryRelayConfig;
  observatory: ObservatoryConfig;
  customObservatory: boolean;
  routeCount: number;
  pooledRouteCount: number;
  legacyThreeHopCount: number;
  twoHopRouteCount: number;
};

export type TopologyMemberSlot = {
  poolId: string;
  nodeId: string;
  name: string;
  order: number;
  x: number;
  y: number;
  width: number;
  height: number;
  member: RelayPoolMemberView;
  runtime?: Runtime;
};

export type TopologyPoolNode = {
  id: string;
  name: string;
  pool: RelayPoolView;
  x: number;
  y: number;
  width: number;
  height: number;
  members: TopologyMemberSlot[];
  activeMemberCount: number;
  revocationPending: number;
};

export type TopologyLegacyRelayNode = {
  id: string;
  relayNodeId: string;
  name: string;
  pendingPoolIds: string[];
  routeIds: string[];
  x: number;
  y: number;
  width: number;
  height: number;
  runtime?: Runtime;
  suspended: boolean;
};

export type TopologyLandingNode = {
  id: string;
  name: string;
  x: number;
  y: number;
  width: number;
  height: number;
  runtime?: Runtime;
  suspended: boolean;
  incomingTwoHop: number;
  incomingPooled: number;
  incomingLegacyThreeHop: number;
};

export type TopologyTwoHopEdge = {
  id: string;
  route: Route;
  entryId: string;
  landingId: string;
  isIpv4Split: boolean;
  desiredEnabled: boolean;
  entryReady: boolean;
  landingReady: boolean;
  suspended: boolean;
  latencyState: "ready" | "slow" | "unreachable" | "stale" | "no-sample" | "unavailable";
  latencyMs?: number;
  checkedAt?: string;
  corridorY: number;
  corridorLeftX: number;
  corridorRightX: number;
  d: string;
  labelX: number;
  labelY: number;
};

export type TopologyLegacyEdge = {
  id: string;
  route: Route;
  entryId: string;
  legacyRelayNodeId: string;
  relayNodeId: string;
  landingId: string;
  pendingRelayPoolId?: string;
  desiredEnabled: boolean;
  entryReady: boolean;
  relayReady: boolean;
  landingReady: boolean;
  suspended: boolean;
  entryToRelayD: string;
  relayToLandingD: string;
  labelX: number;
  labelY: number;
};

export type TopologyEntryPoolEdge = {
  id: string;
  entryId: string;
  poolId: string;
  routes: Route[];
  desiredEnabledCount: number;
  admittedRelayCount: number;
  blocked: boolean;
  entryReady: boolean;
  d: string;
  labelX: number;
  labelY: number;
};

export type TopologyPoolLandingEdge = {
  id: string;
  path: FullPathStatus;
  d: string;
  labelX: number;
  labelY: number;
};

export type TopologyCorridorSummary = {
  dense: boolean;
  summaryY: number;
  totalCount: number;
  healthyCount: number;
  unhealthyCount: number;
  inactiveCount: number;
  staleOrEmptyCount: number;
};

export const TWO_HOP_INLINE_LABEL_LIMIT = 4;

// Conservative proportional-font width estimator (in CSS/SVG px) so wide uppercase ASCII
// characters (e.g. W/M) and CJK ideographs never overflow cards or collide with badges.
export function estimateSvgTextWidth(value: string, fontSizePx: number): number {
  let width = 0;
  for (const ch of value) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp > 0x2e7f) {
      width += fontSizePx * 1.04;
    } else if (ch === "W" || ch === "M" || ch === "@" || ch === "%") {
      width += fontSizePx * 0.96;
    } else if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x30 && cp <= 0x39)) {
      width += fontSizePx * 0.74;
    } else if ("ilI1tfrj.,:;-|! `'\"()[]/".includes(ch)) {
      width += fontSizePx * 0.38;
    } else {
      width += fontSizePx * 0.6;
    }
  }
  return width;
}

export function truncateSvgText(value: string, maxPx: number, fontSizePx: number): string {
  if (estimateSvgTextWidth(value, fontSizePx) <= maxPx) return value;
  const ellipsisPx = fontSizePx * 0.95;
  const budget = Math.max(0, maxPx - ellipsisPx);
  let width = 0;
  let out = "";
  for (const ch of value) {
    const next = estimateSvgTextWidth(ch, fontSizePx);
    if (width + next > budget) break;
    width += next;
    out += ch;
  }
  return `${out.trimEnd()}…`;
}

// In dense top corridors where horizontal bridge lanes sit only ~2-3 SVG units apart,
// resolve pointer clicks strictly inside the shared horizontal bridge span by nearest
// centerline Y; curved left/right transitions outside [commonLeftX, commonRightX] keep their own edge ID.
export function findNearestDenseTwoHopEdge(
  edges: readonly TopologyTwoHopEdge[],
  svgX: number,
  svgY: number,
): TopologyTwoHopEdge | null {
  if (edges.length === 0) return null;
  let commonLeftX = Number.NEGATIVE_INFINITY;
  let commonRightX = Number.POSITIVE_INFINITY;
  for (const edge of edges) {
    if (edge.corridorLeftX > commonLeftX) commonLeftX = edge.corridorLeftX;
    if (edge.corridorRightX < commonRightX) commonRightX = edge.corridorRightX;
  }
  if (svgX < commonLeftX || svgX > commonRightX) return null;
  let best: TopologyTwoHopEdge | null = null;
  let bestDist = Number.POSITIVE_INFINITY;
  for (const edge of edges) {
    const dist = Math.abs(edge.corridorY - svgY);
    if (dist < bestDist) {
      bestDist = dist;
      best = edge;
    }
  }
  return best && bestDist <= 14 ? best : null;
}

function stripEndpointPort(endpoint?: string): string {
  if (!endpoint) return "";
  const trimmed = endpoint.trim();
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end > 1) return trimmed.slice(1, end);
  }
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon > 0 && trimmed.indexOf(":") === lastColon) {
    return trimmed.slice(0, lastColon);
  }
  return trimmed;
}

export type TwoHopLatencyIndex = Map<string, RouteLatency[]>;

export function indexTwoHopLatencies(latencies: Map<string, RouteLatency>): TwoHopLatencyIndex {
  const index: TwoHopLatencyIndex = new Map();
  for (const item of latencies.values()) {
    const bucketKey = latencyKey(item.entryId, item.landingId, item.port);
    const bucket = index.get(bucketKey);
    if (bucket) bucket.push(item);
    else index.set(bucketKey, [item]);
  }
  return index;
}

// Match route-latencies for both unsourced IPv4 (entry/landing/port) and sourced IPv6
// bound-server-transport probes (entry/landing/port/source/address) without guessing on ambiguity.
export function findTwoHopLatency(
  latencies: Map<string, RouteLatency>,
  route: Route,
  landingId: string,
  port: number,
  index?: TwoHopLatencyIndex,
): RouteLatency | undefined {
  const bucketKey = latencyKey(route.entryId, landingId, port);
  let candidates = index
    ? index.get(bucketKey) ?? []
    : [...latencies.values()].filter(
        (item) => item.entryId === route.entryId && item.landingId === landingId && item.port === port,
      );
  if (candidates.length === 0) return undefined;
  if (route.landingAddress) {
    const exact = candidates.filter((item) => stripEndpointPort(item.address) === route.landingAddress);
    if (exact.length > 0) {
      candidates = exact;
    } else {
      const unaddressed = candidates.filter((item) => !stripEndpointPort(item.address));
      if (unaddressed.length === 0) return undefined;
      candidates = unaddressed;
    }
  }
  if (candidates.length === 1) return candidates[0];
  if (route.ingressFamily) {
    const wantIpv6 = route.ingressFamily === "ipv6";
    const byFamily = candidates.filter((item) => {
      const host = stripEndpointPort(item.address) || item.source || "";
      return host !== "" && host.includes(":") === wantIpv6;
    });
    if (byFamily.length > 0) candidates = byFamily;
  }
  if (candidates.length === 1) return candidates[0];
  if (!route.landingAddress && route.ingressFamily !== "ipv6") {
    return latencies.get(bucketKey);
  }
  return undefined;
}

export function evaluateTwoHopLatencyState(
  lat: RouteLatency | undefined,
  now: number,
  latencyFailed: boolean,
): TopologyTwoHopEdge["latencyState"] {
  if (lat?.state === "unavailable") return "unavailable";
  const checkedMs = lat?.checkedAt ? Date.parse(lat.checkedAt) : NaN;
  const isStale = latencyFailed || lat?.state === "stale" || (Number.isFinite(checkedMs) && now - checkedMs > 120_000);
  if (isStale) return "stale";
  if (lat?.state === "unreachable") return "unreachable";
  if (lat?.latencyMs != null && Number.isFinite(lat.latencyMs)) return lat.latencyMs > 100 ? "slow" : "ready";
  return "no-sample";
}

export type TopologyModel = {
  width: number;
  height: number;
  corridorBottomY: number;
  columns: {
    entryX: number;
    poolX: number;
    landingX: number;
  };
  corridor: TopologyCorridorSummary;
  entries: TopologyEntryNode[];
  pools: TopologyPoolNode[];
  legacyRelays: TopologyLegacyRelayNode[];
  landings: TopologyLandingNode[];
  twoHopEdges: TopologyTwoHopEdge[];
  legacyEdges: TopologyLegacyEdge[];
  entryPoolEdges: TopologyEntryPoolEdge[];
  poolLandingEdges: TopologyPoolLandingEdge[];
  allFullPaths: FullPathStatus[];
};

export type InspectedCutoverState = {
  seq: number;
  pending: boolean;
  failed?: string;
  invalidated?: string;
  plan?: SocketCutoverPlan;
  inspectedRevision?: string;
};

// Matches Go model.go ValidIdentifier: 1..128 ASCII [a-zA-Z0-9_-], no dots.
export function isValidIdentifier(value: string): boolean {
  return /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

export function runeLength(value: string): number {
  return Array.from(value).length;
}

// Matches Go model.go validDisplayName (non-empty trimmed, <= 512 runes, no CR/LF/NUL).
export function isValidDisplayName(value: string): boolean {
  return value !== "" && value.trim() === value && runeLength(value) <= MAX_DISPLAY_NAME_RUNES && !/[\r\n\0]/.test(value);
}

// Matches Go relay_pool.go DrainReason check (<= 128 runes, trimmed, no CR/LF/NUL).
export function isValidDrainReason(value: string): boolean {
  return value.trim() === value && runeLength(value) <= MAX_DRAIN_REASON_RUNES && !/[\r\n\0]/.test(value);
}

export function isZeroTimestamp(value?: string): boolean {
  return !value || value.startsWith("0001-");
}

export function routeTopologyKind(route: Route): RouteTopologyKind {
  if (route.relayPoolId) return "pooled";
  if (route.relayId || route.pendingLegacyCutover) return "legacy-three-hop";
  return "two-hop";
}

// Matches control/socket_cutover.go cutoverConsumerMigratable().
export function isCutoverConsumerMigratable(kind: string): boolean {
  return kind === "two-hop-source" || kind === "two-hop-transport" || kind === "legacy-three-hop-landing";
}

export function cutoverConsumerKindLabel(kind: string): string {
  switch (kind) {
    case "two-hop-source":
      return "两跳共享监听源授权";
    case "two-hop-transport":
      return "两跳服务端传输";
    case "legacy-three-hop-landing":
      return "旧三跳下游落地";
    case "legacy-three-hop-relay":
      return "旧三跳中转入站（需先迁移旧三跳）";
    case "pooled-route-landing":
      return "池化三跳固定落地";
    case "pooled-route-relay":
      return "池化三跳中转入站";
    default:
      return kind;
  }
}

export function canStartSocketCutover(
  inspected: InspectedCutoverState | undefined,
  currentTargetRevision: string,
): { allowed: boolean; reason: string; migratableCount: number } {
  if (!inspected) {
    return { allowed: false, reason: "请先执行占用检查，确认全部受影响消费方后再开启切窗。", migratableCount: 0 };
  }
  if (inspected.pending) {
    return { allowed: false, reason: "正在重新检查端口 24000 占用与消费方范围，请稍候…", migratableCount: 0 };
  }
  if (inspected.invalidated) {
    return { allowed: false, reason: inspected.invalidated, migratableCount: 0 };
  }
  if (inspected.failed) {
    return { allowed: false, reason: `最近一次占用检查失败（${inspected.failed}），请重新检查确认影响范围后再开启切窗。`, migratableCount: 0 };
  }
  if (!inspected.plan || !inspected.plan.scopeDigest) {
    return { allowed: false, reason: "缺少有效的切窗范围摘要，请重新检查占用与影响范围。", migratableCount: 0 };
  }
  if (inspected.inspectedRevision !== currentTargetRevision) {
    return { allowed: false, reason: "目标节点修订号已变更，请重新检查占用与影响范围。", migratableCount: 0 };
  }
  if (!inspected.plan.occupied) {
    return { allowed: false, reason: "该地址端口 24000 当前未被单用户监听占用，无需切窗。", migratableCount: 0 };
  }
  if (inspected.plan.deferred || inspected.plan.blockingConsumers.length > 0) {
    return { allowed: false, reason: "存在未就绪、暂停或阻塞的消费方，切窗被延后。", migratableCount: 0 };
  }
  const migratableCount = inspected.plan.consumers.filter((c) => isCutoverConsumerMigratable(c.kind)).length;
  if (migratableCount === 0) {
    return { allowed: false, reason: "当前占用监听上没有可迁移的受影响消费方，控制面将拒绝启动切窗。", migratableCount: 0 };
  }
  return { allowed: true, reason: "", migratableCount };
}

export function normalizeRelayPoolMember(member: RelayPoolMember | RelayPoolMemberView): RelayPoolMember {
  const payload: RelayPoolMember = {
    nodeId: member.nodeId.trim(),
    certificateId: member.certificateId.trim(),
  };
  if (member.ingressIpv4?.trim()) payload.ingressIpv4 = member.ingressIpv4.trim();
  if (member.ingressIpv6?.trim()) payload.ingressIpv6 = member.ingressIpv6.trim();
  if (member.egressIpv4?.trim()) payload.egressIpv4 = member.egressIpv4.trim();
  if (member.egressIpv6?.trim()) payload.egressIpv6 = member.egressIpv6.trim();
  if (member.drained) {
    payload.drained = true;
    const reason = member.drainReason?.trim();
    if (reason) payload.drainReason = reason;
    if (member.drainResumeAt && !isZeroTimestamp(member.drainResumeAt)) {
      payload.drainResumeAt = member.drainResumeAt;
    }
  }
  return payload;
}

// Strict allowlisted RouteChange payload builder so Go's DisallowUnknownFields()
// never rejects view-only BusinessRoute fields on toggle or deletion.
export function buildRouteChangePayload(
  row: Route,
  overrides: {
    enabled?: boolean;
    udp?: boolean;
    hideNative?: boolean;
    delete?: boolean;
    expectedRevision: string;
  },
) {
  const payload: Record<string, unknown> = {
    id: row.id,
    accountId: row.accountId,
    entryId: row.entryId,
    egressId: row.egressId,
    enabled: overrides.enabled ?? row.enabled,
    hideNative: overrides.hideNative ?? row.hideNative,
    expectedRevision: overrides.expectedRevision,
  };
  if (row.ipv4EgressId) payload.ipv4EgressId = row.ipv4EgressId;
  if (row.relayPoolId) payload.relayPoolId = row.relayPoolId;
  const nextUdp = overrides.udp !== undefined ? overrides.udp : row.udp;
  if (nextUdp !== undefined) payload.udp = nextUdp;
  if (overrides.delete) payload.delete = true;
  return payload;
}

export function buildRelayPoolChangePayload(params: {
  id: string;
  name: string;
  revision: string;
  expectedRevision: string;
  strategy: RelayPoolStrategy;
  members: (RelayPoolMember | RelayPoolMemberView)[];
  delete?: boolean;
}) {
  const strategy: RelayPoolStrategy = {
    expected: params.strategy.expected,
    maxRttMs: params.strategy.maxRttMs,
  };
  if (params.strategy.tolerance !== undefined && Number.isFinite(params.strategy.tolerance) && params.strategy.tolerance > 0) {
    strategy.tolerance = params.strategy.tolerance;
  }
  const body: Record<string, unknown> = {
    pool: {
      id: params.id.trim(),
      name: params.name.trim(),
      revision: params.revision || "0",
      strategy,
      members: params.delete ? [] : params.members.map(normalizeRelayPoolMember),
    },
    expectedRevision: params.expectedRevision,
  };
  if (params.delete) body.delete = true;
  return body;
}

export function buildEntryRelayConfigPayload(
  entryId: string,
  expectedRevision: string,
  expectedConfigRevision: string,
  config: EntryRelayConfig,
) {
  const next: Omit<EntryRelayConfig, "revision"> = {};
  if (config.sourceIpv4?.trim()) next.sourceIpv4 = config.sourceIpv4.trim();
  if (config.sourceIpv6?.trim()) next.sourceIpv6 = config.sourceIpv6.trim();
  if (config.observatory) {
    next.observatory = {
      destination: config.observatory.destination.trim(),
      intervalSec: Math.round(config.observatory.intervalSec),
      sampling: Math.round(config.observatory.sampling),
      timeoutSec: Math.round(config.observatory.timeoutSec),
    };
  }
  return {
    entryId,
    expectedRevision,
    expectedConfigRevision: expectedConfigRevision || "0",
    config: next,
  };
}

export function validatePoolDraft(draft: {
  id: string;
  name: string;
  strategy: RelayPoolStrategy;
  members: RelayPoolMember[];
}): string {
  if (!isValidIdentifier(draft.id.trim())) {
    return "中转池 ID 仅允许 1-128 位字母、数字、下划线或连字符（不含点号或空格）。";
  }
  const name = draft.name.trim();
  if (!isValidDisplayName(name)) {
    return `请填写有效的中转池名称（1-${MAX_DISPLAY_NAME_RUNES} 个字符，不含换行或控制字符）。`;
  }
  if (!Number.isInteger(draft.strategy.expected) || draft.strategy.expected < 1 || draft.strategy.expected > 64) {
    return "leastLoad 期望并发节点数（expected）必须是 1 到 64 的整数。";
  }
  if (!Number.isInteger(draft.strategy.maxRttMs) || draft.strategy.maxRttMs < 50 || draft.strategy.maxRttMs > 30000) {
    return "最大参考 RTT（maxRttMs）必须是 50 到 30000 毫秒之间的整数。";
  }
  const tol = draft.strategy.tolerance ?? 0;
  if (!Number.isFinite(tol) || tol < 0 || tol > 1) {
    return "容差比例（tolerance）必须在 0 到 1 之间。";
  }
  const seen = new Set<string>();
  for (const member of draft.members) {
    if (!member.nodeId || !member.certificateId) return "每个中转成员都必须选择已登记的落地节点及其证书。";
    if (seen.has(member.nodeId)) return `中转成员 ${member.nodeId} 重复，请移除重复项。`;
    seen.add(member.nodeId);
    if (!member.ingressIpv4?.trim() && !member.ingressIpv6?.trim()) {
      return `中转成员 ${member.nodeId} 至少需要填写一个公网入站地址（IPv4 或 IPv6）。`;
    }
    if (!member.egressIpv4?.trim() && !member.egressIpv6?.trim()) {
      return `中转成员 ${member.nodeId} 至少需要填写一个出站源地址（IPv4 或 IPv6）。`;
    }
  }
  return "";
}

export function validateObservatoryDraft(config: ObservatoryConfig): string {
  const dest = config.destination.trim();
  if (!dest || utf8ByteLength(dest) > 512) return "请填写有效的 HTTP/HTTPS 探测目标 URL（不超过 512 字节）。";
  try {
    const parsed = new URL(dest);
    if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || !parsed.host || parsed.username || parsed.password || parsed.hash) {
      return "探测目标仅支持无鉴权信息与片段的 http:// 或 https:// 地址。";
    }
  } catch {
    return "探测目标 URL 格式无效。";
  }
  if (!Number.isInteger(config.intervalSec) || config.intervalSec < MIN_OBSERVATORY_INTERVAL_SEC || config.intervalSec > MAX_OBSERVATORY_INTERVAL_SEC) {
    return `探测间隔必须在 ${MIN_OBSERVATORY_INTERVAL_SEC} 到 ${MAX_OBSERVATORY_INTERVAL_SEC} 秒之间。`;
  }
  if (!Number.isInteger(config.sampling) || config.sampling < 1 || config.sampling > 10) {
    return "窗口采样次数（sampling）必须在 1 到 10 之间。";
  }
  if (!Number.isInteger(config.timeoutSec) || config.timeoutSec < 1 || config.timeoutSec > 30 || config.timeoutSec > config.intervalSec) {
    return "单次探测超时必须在 1 到 30 秒之间，且不能大于探测间隔。";
  }
  return "";
}

export function effectiveEntryObservatory(entryId: string, configs?: Record<string, EntryRelayConfig>): { config: ObservatoryConfig; custom: boolean } {
  const custom = configs?.[entryId]?.observatory;
  return custom ? { config: custom, custom: true } : { config: DEFAULT_OBSERVATORY_CONFIG, custom: false };
}

export function observatoryStaleThresholdMs(entryId: string, configs?: Record<string, EntryRelayConfig>): number {
  const { config } = effectiveEntryObservatory(entryId, configs);
  // Entry polls local Xray Observatory at most every 15s; require at least 60s
  // or 3x probe interval before marking telemetry stale to avoid false alarms.
  return Math.max(60_000, Math.max(15, config.intervalSec) * 3 * 1000);
}

export function evaluateObservatorySample(
  sample: EntryObservatoryPathView | undefined,
  entryId: string,
  configs: Record<string, EntryRelayConfig> | undefined,
  now: number,
): EvaluatedObservatorySample {
  if (!sample || isZeroTimestamp(sample.sampledAt)) {
    return { state: "no-sample", stale: false, allSamples: 0, failedSamples: 0 };
  }
  const sampledMs = Date.parse(sample.sampledAt);
  if (!Number.isFinite(sampledMs)) {
    return { state: "no-sample", stale: false, allSamples: 0, failedSamples: 0 };
  }
  const ageMs = Math.max(0, now - sampledMs);
  const stale = ageMs > observatoryStaleThresholdMs(entryId, configs);
  return {
    state: stale ? "stale" : sample.alive ? "healthy" : "unhealthy",
    stale,
    delayMs: sample.delayMs,
    averageMs: sample.averageMs,
    minMs: sample.minMs,
    maxMs: sample.maxMs,
    allSamples: sample.allSamples ?? 0,
    failedSamples: sample.failedSamples ?? 0,
    lastErrorReason: sample.lastErrorReason,
    sampledAt: sample.sampledAt,
    ageMs,
    outboundTag: sample.outboundTag,
  };
}

export function findRouteObservatorySample(
  paths: EntryObservatoryPathView[] | undefined,
  route: Route,
  relayNodeId: string,
): EntryObservatoryPathView | undefined {
  if (!paths?.length || !route.relayPoolId) return undefined;
  const exact = paths.find(
    (p) =>
      p.grantId === route.id &&
      p.entryId === route.entryId &&
      p.poolId === route.relayPoolId &&
      p.relayNodeId === relayNodeId &&
      p.egressId === route.egressId,
  );
  if (exact) return exact;
  return paths.find(
    (p) =>
      (!p.grantId || p.grantId === route.id) &&
      p.entryId === route.entryId &&
      p.poolId === route.relayPoolId &&
      p.relayNodeId === relayNodeId &&
      p.egressId === route.egressId,
  );
}

export function summarizePooledRoute(route: Route, inventory: Inventory, now: number): PooledRouteSummary {
  const pool = (inventory.relayPools ?? []).find((item) => item.id === route.relayPoolId);
  const runtimesById = new Map(inventory.runtimes.map((rt) => [rt.id, rt]));
  const entryRt = runtimesById.get(route.entryId);
  const landingRt = runtimesById.get(route.egressId);
  const admittedSet = new Set(route.activeRelayIds ?? []);
  const paths: FullPathStatus[] = [];

  if (pool) {
    pool.members.forEach((member, index) => {
      const relayRt = runtimesById.get(member.nodeId);
      const sample = findRouteObservatorySample(inventory.observatoryPaths, route, member.nodeId);
      const telemetry = evaluateObservatorySample(sample, route.entryId, inventory.entryRelayConfigs, now);
      const admitted =
        route.activeRelayIds !== undefined
          ? admittedSet.has(member.nodeId)
          : (route.activeRelays ?? 0) > 0 && !member.drained && !member.nodeSuspended && member.runtimeReady;
      paths.push({
        id: `${route.id}/${member.nodeId}`,
        route,
        entryId: route.entryId,
        poolId: pool.id,
        relayNodeId: member.nodeId,
        egressId: route.egressId,
        memberOrder: index + 1,
        desiredRouteEnabled: route.enabled,
        memberDrained: member.drained,
        drainReason: member.drainReason,
        drainResumeAt: member.drainResumeAt,
        nodeSuspended: member.nodeSuspended || isSuspensionActive(inventory.availability?.nodes[member.nodeId], now),
        admitted,
        entryRuntimeReady: entryRt?.runtimeReady ?? false,
        relayRuntimeReady: member.runtimeReady,
        landingRuntimeReady: landingRt?.runtimeReady ?? false,
        entryDesiredRev: entryRt?.revision ?? "0",
        entryAppliedRev: entryRt?.appliedRevision ?? "0",
        relayDesiredRev: relayRt?.revision ?? "0",
        relayAppliedRev: relayRt?.appliedRevision ?? "0",
        landingDesiredRev: landingRt?.revision ?? "0",
        landingAppliedRev: landingRt?.appliedRevision ?? "0",
        telemetry,
      });
    });
  }

  let healthyCount = 0;
  let unhealthyCount = 0;
  let staleCount = 0;
  let noSampleCount = 0;
  let bestDelayMs: number | undefined;
  for (const path of paths) {
    if (!path.admitted) continue;
    if (path.telemetry.state === "healthy") {
      healthyCount++;
      if (path.telemetry.delayMs != null && (bestDelayMs === undefined || path.telemetry.delayMs < bestDelayMs)) {
        bestDelayMs = path.telemetry.delayMs;
      }
    } else if (path.telemetry.state === "unhealthy") {
      unhealthyCount++;
    } else if (path.telemetry.state === "stale") {
      staleCount++;
    } else {
      noSampleCount++;
    }
  }
  const admittedCount = route.activeRelayIds ? route.activeRelayIds.length : route.activeRelays ?? 0;
  return {
    route,
    pool,
    paths,
    admittedCount,
    totalMembers: pool?.members.length ?? 0,
    healthyCount,
    unhealthyCount,
    staleCount,
    noSampleCount,
    bestDelayMs,
    blockedByEmptyPool: route.enabled && admittedCount === 0,
  };
}

export function formatSampleAge(sampledAt: string | undefined, now: number): string {
  if (!sampledAt || isZeroTimestamp(sampledAt)) return "尚无样本";
  const ts = Date.parse(sampledAt);
  if (!Number.isFinite(ts)) return "尚无样本";
  const sec = Math.max(0, Math.floor((now - ts) / 1000));
  if (sec < 5) return "刚刚";
  if (sec < 60) return `${sec} 秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  return `${Math.floor(sec / 3600)} 小时前`;
}

export function formatRevisionReceipt(desired: string | undefined, applied: string | undefined, ready: boolean): string {
  const d = desired && desired !== "0" ? `R${desired}` : "R—";
  const a = applied && applied !== "0" ? `R${applied}` : "无回执";
  if (ready && desired && applied === desired) return `已应用 ${a}`;
  if (applied && applied !== "0" && desired && applied !== desired) return `回执 ${a} / 期望 ${d}`;
  return ready ? `已应用 ${d}` : `待回执（期望 ${d}）`;
}

export function cutoverPhaseLabel(phase: string): string {
  switch (phase) {
    case "starting":
      return "切窗启动中";
    case "listener-pending":
      return "等待目标端口 24000 回执";
    case "entries-applying":
      return "正在切换入口配置";
    case "entries-pending":
      return "等待入口应用回执";
    case "rollback-applying":
      return "正在回滚切窗";
    case "rollback-pending":
      return "等待回滚回执";
    case "completed":
      return "已完成";
    case "rolled-back":
      return "已回滚";
    default:
      return phase;
  }
}

export function buildTopologyModel(params: {
  inventory: Inventory;
  names: Map<string, string>;
  latencies: Map<string, RouteLatency>;
  now: number;
  latencyFailed: boolean;
  filter: TopologyFilter;
  entryFilter?: string;
}): TopologyModel {
  const { inventory, names, latencies, now, latencyFailed, filter, entryFilter } = params;
  const nodeName = (id: string) => names.get(id) ?? id;
  const runtimesById = new Map(inventory.runtimes.map((rt) => [rt.id, rt]));
  const poolsAll = inventory.relayPools ?? [];
  const routesRaw = inventory.routes.filter((r) => !entryFilter || r.entryId === entryFilter);

  const summaryByRouteId = new Map<string, PooledRouteSummary>();
  for (const route of routesRaw) {
    if (routeTopologyKind(route) === "pooled") {
      summaryByRouteId.set(route.id, summarizePooledRoute(route, inventory, now));
    }
  }

  const latencyIndex = indexTwoHopLatencies(latencies);

  const routeMatchesFilter = (route: Route): boolean => {
    const kind = routeTopologyKind(route);
    if (filter === "pooled") return kind === "pooled" || kind === "legacy-three-hop";
    if (filter === "two-hop") return kind === "two-hop";
    if (filter === "attention") {
      if (kind === "pooled") {
        const s = summaryByRouteId.get(route.id);
        if (!s) return true;
        return (
          s.blockedByEmptyPool ||
          s.unhealthyCount > 0 ||
          s.staleCount > 0 ||
          s.noSampleCount > 0 ||
          !!route.retiringLegacyTransport ||
          !route.enabled ||
          route.state !== "verified"
        );
      }
      if (kind === "legacy-three-hop") {
        return !!route.pendingLegacyCutover || !route.enabled || route.state !== "verified";
      }
      const primaryLat = findTwoHopLatency(latencies, route, route.egressId, route.port, latencyIndex);
      const splitLat =
        route.ipv4EgressId && route.ipv4EgressId !== route.egressId
          ? findTwoHopLatency(latencies, route, route.ipv4EgressId, route.ipv4Port ?? 0, latencyIndex)
          : undefined;
      const latNeedsAttention = (lat: RouteLatency | undefined) => {
        const state = evaluateTwoHopLatencyState(lat, now, latencyFailed);
        return state !== "ready" && state !== "slow";
      };
      return (
        !route.enabled ||
        route.state !== "verified" ||
        latNeedsAttention(primaryLat) ||
        (!!route.ipv4EgressId && route.ipv4EgressId !== route.egressId && latNeedsAttention(splitLat))
      );
    }
    return true;
  };

  const routes = routesRaw.filter(routeMatchesFilter);
  const twoHopRoutes = routes.filter((r) => routeTopologyKind(r) === "two-hop");
  const legacyThreeHopRoutes = routes.filter((r) => routeTopologyKind(r) === "legacy-three-hop");
  const pooledRoutes = routes.filter((r) => routeTopologyKind(r) === "pooled");

  const entryIds = new Set<string>();
  for (const rt of inventory.runtimes) {
    if (rt.role === "entry" && (!entryFilter || rt.id === entryFilter)) entryIds.add(rt.id);
  }
  for (const route of routes) entryIds.add(route.entryId);

  const visiblePools =
    filter === "two-hop"
      ? []
      : filter === "attention"
        ? poolsAll.filter(
            (p) =>
              (p.revocation && !p.revocation.complete) ||
              p.members.some((m) => m.drained || m.nodeSuspended || !m.runtimeReady) ||
              pooledRoutes.some((r) => r.relayPoolId === p.id) ||
              legacyThreeHopRoutes.some((r) => r.pendingRelayPoolId === p.id),
          )
        : poolsAll;

  const landingIds = new Set<string>();
  for (const route of routes) {
    landingIds.add(route.egressId);
    if (route.ipv4EgressId) landingIds.add(route.ipv4EgressId);
  }
  if (filter === "all" && !entryFilter) {
    const relayOnlySet = new Set(poolsAll.flatMap((p) => p.members.map((m) => m.nodeId)));
    for (const rt of inventory.runtimes) {
      if (rt.role === "landing" && (!relayOnlySet.has(rt.id) || landingIds.has(rt.id))) {
        landingIds.add(rt.id);
      }
    }
  }

  // Sort pool / three-hop participating entries and landings first so active relay-pool
  // flows align horizontally near the top of the viewport instead of sitting far below two-hop-only nodes.
  const entryTier = (id: string) => {
    if (pooledRoutes.some((r) => r.entryId === id) || legacyThreeHopRoutes.some((r) => r.entryId === id)) return 0;
    if (twoHopRoutes.some((r) => r.entryId === id)) return 1;
    return 2;
  };
  const landingTier = (id: string) => {
    if (pooledRoutes.some((r) => r.egressId === id) || legacyThreeHopRoutes.some((r) => r.egressId === id)) return 0;
    if (twoHopRoutes.some((r) => r.egressId === id || r.ipv4EgressId === id)) return 1;
    return 2;
  };

  const sortedEntryIds = [...entryIds].sort((a, b) => entryTier(a) - entryTier(b) || nodeName(a).localeCompare(nodeName(b)));
  const sortedLandingIds = [...landingIds].sort((a, b) => landingTier(a) - landingTier(b) || nodeName(a).localeCompare(nodeName(b)));

  // Fixed 1:1 CSS-pixel SVG coordinate geometry (capped at max-width: 1040px in CSS so wide screens never magnify text)
  const width = 1040;
  const colEntryX = 20;
  const entryW = 216;
  const entryH = 64;
  const colPoolX = 356;
  const poolW = 328;
  const colLandingX = 804;
  const landingW = 216;
  const landingH = 64;
  const baseCorridorLeftX = colPoolX - 24; // 332, strictly left of middle column
  const baseCorridorRightX = colPoolX + poolW + 24; // 708, strictly right of middle column

  // Count total two-hop segments so EVERY two-hop horizontal bridge lane fits strictly
  // above topStartY without ever intersecting middle-column cards, while capping corridor
  // height in dense clusters (> 4 two-hop routes) so the columns stay immediately visible.
  let totalTwoHopLanes = 0;
  for (const route of twoHopRoutes) {
    totalTwoHopLanes += 1;
    if (route.ipv4EgressId && route.ipv4EgressId !== route.egressId) totalTwoHopLanes += 1;
  }
  const denseTwoHop = totalTwoHopLanes > TWO_HOP_INLINE_LABEL_LIMIT;
  const corridorSummaryY = 40;
  const laneStartY = denseTwoHop ? 58 : 42;
  const laneStepY = 17;
  const denseCorridorSpan = 44;
  const corridorBottomY =
    totalTwoHopLanes === 0
      ? 30
      : denseTwoHop
        ? laneStartY + denseCorridorSpan + 6
        : laneStartY + (totalTwoHopLanes - 1) * laneStepY + 12;
  const topStartY = totalTwoHopLanes === 0 ? 38 : denseTwoHop ? corridorBottomY + 14 : corridorBottomY + 16;
  const rowGap = 10;

  const entries: TopologyEntryNode[] = sortedEntryIds.map((id, index) => {
    const rt = runtimesById.get(id);
    const { config, custom } = effectiveEntryObservatory(id, inventory.entryRelayConfigs);
    const entryRoutes = routes.filter((r) => r.entryId === id);
    return {
      id,
      name: nodeName(id),
      x: colEntryX,
      y: topStartY + index * (entryH + rowGap),
      width: entryW,
      height: entryH,
      runtime: rt,
      suspended: isSuspensionActive(inventory.availability?.nodes[id], now),
      relayConfig: inventory.entryRelayConfigs?.[id],
      observatory: config,
      customObservatory: custom,
      routeCount: entryRoutes.length,
      pooledRouteCount: entryRoutes.filter((r) => routeTopologyKind(r) === "pooled").length,
      legacyThreeHopCount: entryRoutes.filter((r) => routeTopologyKind(r) === "legacy-three-hop").length,
      twoHopRouteCount: entryRoutes.filter((r) => routeTopologyKind(r) === "two-hop").length,
    };
  });

  let middleCursorY = topStartY;
  const pools: TopologyPoolNode[] = visiblePools.map((pool) => {
    const headerH = 44;
    const memberH = 28;
    const memberGap = 6;
    const footerPad = 10;
    const bodyH = pool.members.length > 0 ? pool.members.length * memberH + (pool.members.length - 1) * memberGap : 26;
    const h = headerH + bodyH + footerPad;
    const y = middleCursorY;
    middleCursorY += h + 14;
    const members: TopologyMemberSlot[] = pool.members.map((member, idx) => ({
      poolId: pool.id,
      nodeId: member.nodeId,
      name: nodeName(member.nodeId),
      order: idx + 1,
      x: colPoolX + 12,
      y: y + headerH + idx * (memberH + memberGap),
      width: poolW - 24,
      height: memberH,
      member,
      runtime: runtimesById.get(member.nodeId),
    }));
    const revPending = (pool.revocation?.pendingEntries.length ?? 0) + (pool.revocation?.pendingLandings.length ?? 0);
    return {
      id: pool.id,
      name: pool.name,
      pool,
      x: colPoolX,
      y,
      width: poolW,
      height: h,
      members,
      activeMemberCount: pool.members.filter((m) => !m.drained && !m.nodeSuspended && m.runtimeReady).length,
      revocationPending: revPending,
    };
  });

  // Group legacy single-relay 3-hop routes in the middle column beneath relay pools
  const legacyGroupMap = new Map<string, { relayNodeId: string; pendingPoolIds: Set<string>; routeIds: string[] }>();
  for (const route of legacyThreeHopRoutes) {
    const relayNodeId = route.relayId || `legacy-${route.id}`;
    const existing = legacyGroupMap.get(relayNodeId) ?? { relayNodeId, pendingPoolIds: new Set<string>(), routeIds: [] };
    if (route.pendingRelayPoolId) existing.pendingPoolIds.add(route.pendingRelayPoolId);
    existing.routeIds.push(route.id);
    legacyGroupMap.set(relayNodeId, existing);
  }
  const legacyRelays: TopologyLegacyRelayNode[] = [...legacyGroupMap.values()]
    .sort((a, b) => nodeName(a.relayNodeId).localeCompare(nodeName(b.relayNodeId)))
    .map((group) => {
      const h = 56;
      const y = middleCursorY;
      middleCursorY += h + 12;
      return {
        id: `legacy-relay:${group.relayNodeId}`,
        relayNodeId: group.relayNodeId,
        name: nodeName(group.relayNodeId),
        pendingPoolIds: [...group.pendingPoolIds].sort(),
        routeIds: group.routeIds,
        x: colPoolX,
        y,
        width: poolW,
        height: h,
        runtime: runtimesById.get(group.relayNodeId),
        suspended: isSuspensionActive(inventory.availability?.nodes[group.relayNodeId], now),
      };
    });

  const landings: TopologyLandingNode[] = sortedLandingIds.map((id, index) => {
    const rt = runtimesById.get(id);
    const incomingTwoHop = twoHopRoutes.filter((r) => r.egressId === id || r.ipv4EgressId === id).length;
    const incomingPooled = pooledRoutes.filter((r) => r.egressId === id).length;
    const incomingLegacyThreeHop = legacyThreeHopRoutes.filter((r) => r.egressId === id).length;
    return {
      id,
      name: nodeName(id),
      x: colLandingX,
      y: topStartY + index * (landingH + rowGap),
      width: landingW,
      height: landingH,
      runtime: rt,
      suspended: isSuspensionActive(inventory.availability?.nodes[id], now),
      incomingTwoHop,
      incomingPooled,
      incomingLegacyThreeHop,
    };
  });

  const entryById = new Map(entries.map((e) => [e.id, e]));
  const poolById = new Map(pools.map((p) => [p.id, p]));
  const legacyRelayByRelayId = new Map(legacyRelays.map((r) => [r.relayNodeId, r]));
  const landingById = new Map(landings.map((l) => [l.id, l]));

  // Build two-hop direct segmented corridor paths:
  // rise cleanly in left gutter -> strictly horizontal bridge across top corridor (above all middle cards) -> descend cleanly in right gutter.
  const twoHopEdges: TopologyTwoHopEdge[] = [];
  let twoHopIndex = 0;
  for (const route of twoHopRoutes) {
    const entryNode = entryById.get(route.entryId);
    if (!entryNode) continue;
    const targets: { landingId: string; isIpv4Split: boolean; port: number }[] = [
      { landingId: route.egressId, isIpv4Split: false, port: route.port },
    ];
    if (route.ipv4EgressId && route.ipv4EgressId !== route.egressId) {
      targets.push({ landingId: route.ipv4EgressId, isIpv4Split: true, port: route.ipv4Port ?? 0 });
    }
    for (const target of targets) {
      const landingNode = landingById.get(target.landingId);
      if (!landingNode) continue;
      const sx = entryNode.x + entryNode.width;
      const sy = entryNode.y + 14 + (twoHopIndex % 3) * 10;
      const tx = landingNode.x;
      const ty = landingNode.y + 14 + (twoHopIndex % 3) * 10;
      const edgeCorridorLeftX = denseTwoHop ? baseCorridorLeftX - (twoHopIndex % 5) * 4 : baseCorridorLeftX;
      const edgeCorridorRightX = denseTwoHop ? baseCorridorRightX + (twoHopIndex % 5) * 4 : baseCorridorRightX;
      const corridorY = denseTwoHop
        ? Math.round((laneStartY + (twoHopIndex / Math.max(1, totalTwoHopLanes - 1)) * denseCorridorSpan) * 10) / 10
        : laneStartY + twoHopIndex * laneStepY;
      const leftCtrlX = Math.round((sx + edgeCorridorLeftX) / 2);
      const rightCtrlX = Math.round((edgeCorridorRightX + tx) / 2);
      // 3-segment SVG path: left rise C -> strictly horizontal bridge L inside corridor -> right descent C
      const d = `M ${sx} ${sy} C ${leftCtrlX} ${sy}, ${leftCtrlX} ${corridorY}, ${edgeCorridorLeftX} ${corridorY} L ${edgeCorridorRightX} ${corridorY} C ${rightCtrlX} ${corridorY}, ${rightCtrlX} ${ty}, ${tx} ${ty}`;
      const labelOffset = ((twoHopIndex % 3) - 1) * 124;
      const labelX = Math.round((baseCorridorLeftX + baseCorridorRightX) / 2 + labelOffset);
      const labelY = corridorY;
      const lat = findTwoHopLatency(latencies, route, target.landingId, target.port, latencyIndex);
      const latencyState = evaluateTwoHopLatencyState(lat, now, latencyFailed);
      const suspended =
        route.state === "temporarily-suspended" ||
        isSuspensionActive(inventory.availability?.nodes[route.entryId], now) ||
        isSuspensionActive(inventory.availability?.nodes[target.landingId], now);
      twoHopEdges.push({
        id: `twohop:${route.id}:${target.landingId}`,
        route,
        entryId: route.entryId,
        landingId: target.landingId,
        isIpv4Split: target.isIpv4Split,
        desiredEnabled: route.enabled,
        entryReady: entryNode.runtime?.runtimeReady ?? false,
        landingReady: landingNode.runtime?.runtimeReady ?? false,
        suspended,
        latencyState,
        latencyMs: lat?.latencyMs,
        checkedAt: lat?.checkedAt,
        corridorY,
        corridorLeftX: edgeCorridorLeftX,
        corridorRightX: edgeCorridorRightX,
        d,
        labelX,
        labelY,
      });
      twoHopIndex++;
    }
  }

  let corridorHealthy = 0;
  let corridorUnhealthy = 0;
  let corridorInactive = 0;
  let corridorStaleOrEmpty = 0;
  for (const edge of twoHopEdges) {
    if (!edge.desiredEnabled || edge.suspended || edge.latencyState === "unavailable") {
      corridorInactive++;
    } else if (edge.latencyState === "ready" || edge.latencyState === "slow") {
      corridorHealthy++;
    } else if (edge.latencyState === "unreachable") {
      corridorUnhealthy++;
    } else {
      corridorStaleOrEmpty++;
    }
  }
  const corridor: TopologyCorridorSummary = {
    dense: denseTwoHop,
    summaryY: corridorSummaryY,
    totalCount: twoHopEdges.length,
    healthyCount: corridorHealthy,
    unhealthyCount: corridorUnhealthy,
    inactiveCount: corridorInactive,
    staleOrEmptyCount: corridorStaleOrEmpty,
  };

  // Build Legacy Three-Hop edges (Entry -> Legacy Single Relay -> Fixed Landing)
  const legacyEdges: TopologyLegacyEdge[] = [];
  legacyThreeHopRoutes.forEach((route, idx) => {
    const entryNode = entryById.get(route.entryId);
    const relayKey = route.relayId || `legacy-${route.id}`;
    const legacyRelayNode = legacyRelayByRelayId.get(relayKey);
    const landingNode = landingById.get(route.egressId);
    if (!entryNode || !legacyRelayNode || !landingNode) return;
    const sx = entryNode.x + entryNode.width;
    const sy = entryNode.y + entryNode.height - 14;
    const rxIn = legacyRelayNode.x;
    const ry = legacyRelayNode.y + legacyRelayNode.height / 2 + ((idx % 3) - 1) * 5;
    const rxOut = legacyRelayNode.x + legacyRelayNode.width;
    const tx = landingNode.x;
    const ty = landingNode.y + landingNode.height - 14;
    const leftMidX = Math.round((sx + rxIn) / 2);
    const rightMidX = Math.round((rxOut + tx) / 2);
    const suspended =
      route.state === "temporarily-suspended" ||
      isSuspensionActive(inventory.availability?.nodes[route.entryId], now) ||
      isSuspensionActive(inventory.availability?.nodes[relayKey], now) ||
      isSuspensionActive(inventory.availability?.nodes[route.egressId], now);
    legacyEdges.push({
      id: `legacy:${route.id}`,
      route,
      entryId: route.entryId,
      legacyRelayNodeId: legacyRelayNode.id,
      relayNodeId: relayKey,
      landingId: route.egressId,
      pendingRelayPoolId: route.pendingRelayPoolId,
      desiredEnabled: route.enabled,
      entryReady: entryNode.runtime?.runtimeReady ?? false,
      relayReady: legacyRelayNode.runtime?.runtimeReady ?? false,
      landingReady: landingNode.runtime?.runtimeReady ?? false,
      suspended,
      entryToRelayD: `M ${sx} ${sy} C ${leftMidX} ${sy}, ${leftMidX} ${ry}, ${rxIn} ${ry}`,
      relayToLandingD: `M ${rxOut} ${ry} C ${rightMidX} ${ry}, ${rightMidX} ${ty}, ${tx} ${ty}`,
      labelX: rightMidX,
      labelY: Math.round((ry + ty) / 2) - 4,
    });
  });

  // Build Entry -> RelayPool trunk edges
  const entryPoolMap = new Map<string, Route[]>();
  const allFullPaths: FullPathStatus[] = [];
  for (const route of pooledRoutes) {
    if (!route.relayPoolId) continue;
    const key = `${route.entryId}::${route.relayPoolId}`;
    entryPoolMap.set(key, [...(entryPoolMap.get(key) ?? []), route]);
    const summary = summaryByRouteId.get(route.id);
    if (summary) allFullPaths.push(...summary.paths);
  }

  const entryPoolEdges: TopologyEntryPoolEdge[] = [];
  let epIdx = 0;
  for (const [key, epRoutes] of entryPoolMap) {
    const [entryId, poolId] = key.split("::");
    const entryNode = entryById.get(entryId);
    const poolNode = poolById.get(poolId);
    if (!entryNode || !poolNode) continue;
    const sx = entryNode.x + entryNode.width;
    const sy = entryNode.y + entryNode.height / 2 + ((epIdx % 3) - 1) * 7;
    const tx = poolNode.x;
    const ty = poolNode.y + 22 + ((epIdx % 3) - 1) * 6;
    const midX = Math.round((sx + tx) / 2);
    const d = `M ${sx} ${sy} C ${midX} ${sy}, ${midX} ${ty}, ${tx} ${ty}`;
    const desiredEnabledCount = epRoutes.filter((r) => r.enabled).length;
    const admittedRelayCount = Math.max(0, ...epRoutes.map((r) => r.activeRelayIds?.length ?? r.activeRelays ?? 0));
    entryPoolEdges.push({
      id: `ep:${entryId}:${poolId}`,
      entryId,
      poolId,
      routes: epRoutes,
      desiredEnabledCount,
      admittedRelayCount,
      blocked: desiredEnabledCount > 0 && admittedRelayCount === 0,
      entryReady: entryNode.runtime?.runtimeReady ?? false,
      d,
      labelX: midX,
      labelY: Math.round((sy + ty) / 2) - 4,
    });
    epIdx++;
  }

  // Build Pool Member -> Fixed Landing full-path edges
  const poolLandingEdges: TopologyPoolLandingEdge[] = [];
  const memberOutgoingIndex = new Map<string, number>();
  for (const path of allFullPaths) {
    const poolNode = poolById.get(path.poolId);
    const landingNode = landingById.get(path.egressId);
    if (!poolNode || !landingNode) continue;
    const memberSlot = poolNode.members.find((m) => m.nodeId === path.relayNodeId);
    if (!memberSlot) continue;
    const outKey = `${path.poolId}:${path.relayNodeId}`;
    const idx = memberOutgoingIndex.get(outKey) ?? 0;
    memberOutgoingIndex.set(outKey, idx + 1);
    const sx = memberSlot.x + memberSlot.width;
    const sy = memberSlot.y + memberSlot.height / 2;
    const tx = landingNode.x;
    const ty = landingNode.y + landingNode.height / 2 + ((idx % 3) - 1) * 8;
    const midX = Math.round((sx + tx) / 2);
    const d = `M ${sx} ${sy} C ${midX} ${sy}, ${midX} ${ty}, ${tx} ${ty}`;
    poolLandingEdges.push({
      id: path.id,
      path,
      d,
      labelX: midX,
      labelY: Math.round((sy + ty) / 2) - 4,
    });
  }

  const bottomEntry = entries.length ? entries[entries.length - 1].y + entryH : topStartY + 80;
  const bottomMiddle = middleCursorY > topStartY ? middleCursorY : topStartY + 80;
  const bottomLanding = landings.length ? landings[landings.length - 1].y + landingH : topStartY + 80;
  const height = Math.max(220, Math.max(bottomEntry, bottomMiddle, bottomLanding) + 24);

  return {
    width,
    height,
    corridorBottomY,
    columns: {
      entryX: colEntryX,
      poolX: colPoolX,
      landingX: colLandingX,
    },
    corridor,
    entries,
    pools,
    legacyRelays,
    landings,
    twoHopEdges,
    legacyEdges,
    entryPoolEdges,
    poolLandingEdges,
    allFullPaths,
  };
}

export function isPathSelectedOrConnected(selection: TopologySelection, path: FullPathStatus): boolean {
  if (!selection) return true;
  switch (selection.kind) {
    case "entry":
      return path.entryId === selection.id;
    case "pool":
      return path.poolId === selection.id;
    case "member":
      return path.poolId === selection.poolId && path.relayNodeId === selection.nodeId;
    case "landing":
      return path.egressId === selection.id;
    case "path":
      return path.id === selection.id;
    case "two-hop":
    case "legacy-relay":
    case "legacy-route":
      return false;
  }
}

export function isTwoHopSelectedOrConnected(selection: TopologySelection, edge: TopologyTwoHopEdge): boolean {
  if (!selection) return true;
  switch (selection.kind) {
    case "entry":
      return edge.entryId === selection.id;
    case "landing":
      return edge.landingId === selection.id;
    case "two-hop":
      return edge.id === selection.id;
    default:
      return false;
  }
}

export function isLegacyEdgeSelectedOrConnected(selection: TopologySelection, edge: TopologyLegacyEdge): boolean {
  if (!selection) return true;
  switch (selection.kind) {
    case "entry":
      return edge.entryId === selection.id;
    case "landing":
      return edge.landingId === selection.id;
    case "legacy-relay":
      return edge.legacyRelayNodeId === selection.id;
    case "legacy-route":
      return edge.id === selection.id;
    case "pool":
      return !!edge.pendingRelayPoolId && edge.pendingRelayPoolId === selection.id;
    default:
      return false;
  }
}

export function isEntryPoolSelectedOrConnected(selection: TopologySelection, edge: TopologyEntryPoolEdge, allPaths: FullPathStatus[]): boolean {
  if (!selection) return true;
  switch (selection.kind) {
    case "entry":
      return edge.entryId === selection.id;
    case "pool":
      return edge.poolId === selection.id;
    case "member":
      return edge.poolId === selection.poolId;
    case "landing":
      return allPaths.some((p) => p.entryId === edge.entryId && p.poolId === edge.poolId && p.egressId === selection.id);
    case "path":
      return allPaths.some((p) => p.id === selection.id && p.entryId === edge.entryId && p.poolId === edge.poolId);
    case "two-hop":
    case "legacy-relay":
    case "legacy-route":
      return false;
  }
}
