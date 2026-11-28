export type Plan = { totalBytes: string; expiryTime: string; resetDays: number; enabled: boolean };
export type Account = { retiredUsageBytes?: string; account: { id: string; displayName: string; desiredRevision: string; plan: Plan }; usage: { baseline: string; observed: string }[]; schedule: { nextResetAt: string }; traffic: Record<string, { uploadBytes: string; downloadBytes: string }> };

export type RelayPoolStrategy = {
  expected: number;
  maxRttMs: number;
  tolerance?: number;
};

export type RelayPoolMember = {
  nodeId: string;
  certificateId: string;
  ingressIpv4?: string;
  ingressIpv6?: string;
  egressIpv4?: string;
  egressIpv6?: string;
  drained?: boolean;
  drainReason?: string;
  drainResumeAt?: string;
};

export type RelayPoolMemberView = {
  nodeId: string;
  certificateId: string;
  ingressIpv4?: string;
  ingressIpv6?: string;
  egressIpv4?: string;
  egressIpv6?: string;
  drained: boolean;
  drainReason?: string;
  drainResumeAt?: string;
  nodeSuspended: boolean;
  runtimeReady: boolean;
};

export type RelayPoolRevocationStatus = {
  pendingEntries: string[];
  pendingLandings: string[];
  complete: boolean;
};

export type RelayPoolView = {
  id: string;
  name: string;
  revision: string;
  strategy: RelayPoolStrategy;
  members: RelayPoolMemberView[];
  routeIds: string[];
  revocation?: RelayPoolRevocationStatus;
};

export type RelayPoolChangeResult = {
  poolId: string;
  revision: string;
  deleted?: boolean;
  revocation?: RelayPoolRevocationStatus;
};

export type ObservatoryConfig = {
  destination: string;
  intervalSec: number;
  sampling: number;
  timeoutSec: number;
};

export type EntryRelayConfig = {
  revision?: string;
  sourceIpv4?: string;
  sourceIpv6?: string;
  observatory?: ObservatoryConfig;
};

export type EntryObservatoryPathView = {
  entryId: string;
  grantId?: string;
  poolId: string;
  relayNodeId: string;
  egressId: string;
  outboundTag: string;
  alive: boolean;
  delayMs: number;
  averageMs?: number;
  minMs?: number;
  maxMs?: number;
  allSamples?: number;
  failedSamples?: number;
  lastErrorReason?: string;
  sampledAt: string;
};

export type SocketCutoverConsumer = {
  kind: string;
  entryId: string;
  entryCertificateId: string;
  peerKey?: string;
  source?: string;
  egressIp?: string;
  udp?: boolean;
  serverTransportId?: string;
  grantId?: string;
  credentialId?: string;
  bindingId?: string;
};

export type SocketCutoverPlan = {
  targetNodeId: string;
  address: string;
  port: number;
  occupied: boolean;
  deferred: boolean;
  scopeDigest?: string;
  blockingConsumers: string[];
  consumers: SocketCutoverConsumer[];
};

export type SocketCutoverView = {
  id: string;
  targetNodeId: string;
  address: string;
  port: number;
  phase: string;
  listenerRevision: string;
  listenerApplied: boolean;
  pendingEntries: string[];
  consumerEntryIds: string[];
  completed?: boolean;
  rolledBack?: boolean;
};

export type Route = {
  udp?: boolean;
  clientChainId?: string;
  relayPoolId?: string;
  pendingRelayPoolId?: string;
  pendingLegacyCutover?: boolean;
  retiringLegacyTransport?: boolean;
  relayId?: string;
  activeRelays?: number;
  activeRelayIds?: string[];
  landingAddress?: string;
  expectedExit?: string;
  egressIp?: string;
  ingressFamily?: string;
  name?: string;
  port: number;
  ipv4Port?: number;
  id: string;
  accountId: string;
  entryId: string;
  egressId: string;
  ipv4EgressId?: string;
  enabled: boolean;
  hideNative: boolean;
  state: string;
};

export type Runtime = {
  id: string;
  certificateId?: string;
  hostId?: string;
  role: string;
  revision: string;
  appliedRevision?: string;
  runtimeReady: boolean;
  relayPoolCapable?: boolean;
  publicIpv4?: string;
  publicIpv6?: string;
  egressIp?: string;
  occupiedPort24000?: string[];
  reportedAt: string;
  peers: string[];
};

export type Suspension = { reason: string; changedAt: string; resumeAt?: string };

export type Inventory = {
  state: string;
  availability?: { revision: string; nodes: Record<string, Suspension> };
  accounts: Account[];
  endpoints: { id: string; entryId: string; nodeId: string; name: string; retired: boolean; nextResetAt?: string }[];
  routes: Route[];
  runtimes: Runtime[];
  nodes: { id: string; name: string; centerAgentId?: string }[];
  relayPools?: RelayPoolView[];
  entryRelayConfigs?: Record<string, EntryRelayConfig>;
  observatoryPaths?: EntryObservatoryPathView[];
  socketCutovers?: SocketCutoverView[];
};
