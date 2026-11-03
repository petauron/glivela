export type Plan = { totalBytes: string; expiryTime: string; resetDays: number; enabled: boolean };
export type Account = { account: { id: string; displayName: string; desiredRevision: string; plan: Plan }; usage: { baseline: string; observed: string }[]; schedule: { nextResetAt: string }; traffic: Record<string, { uploadBytes: string; downloadBytes: string }> };
export type Route = { id: string; accountId: string; entryId: string; egressId: string; ipv4EgressId?: string; enabled: boolean; hideNative: boolean; state: string };
export type ClientChain = { shared?: boolean; transport?: string; sourceIpv6?: string; serverIpv6?: string; port: number; id: string; accountId: string; entryId: string; egressId: string; name: string; enabled: boolean };
export type Runtime = { id: string; hostId?: string; role: string; revision: string; runtimeReady: boolean; reportedAt: string; peers: string[] };
export type Suspension = { reason: string; changedAt: string; resumeAt?: string };
export type Inventory = { clientChains?: ClientChain[]; state: string; availability?: { revision: string; nodes: Record<string, Suspension> }; accounts: Account[]; endpoints: { id: string; entryId: string; nodeId: string; name: string; retired: boolean; nextResetAt?: string }[]; routes: Route[]; runtimes: Runtime[]; nodes: { id: string; name: string; centerAgentId?: string }[] };

