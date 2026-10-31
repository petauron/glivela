import type { Account } from "./control-types";
export function amount(value: string) { return `${(Number(BigInt(value) / 1048576n) / 1024).toFixed(2)} GiB`; }
export function used(account: Account) { return account.usage.reduce((sum, item) => sum + BigInt(item.observed) - BigInt(item.baseline), 0n).toString(); }
export function reported(value: string) {
 const at=Date.parse(value); if (!Number.isFinite(at) || value.startsWith("0001-")) return "尚无上报";
 const seconds=Math.max(0,(Date.now()-at)/1000);
 if(seconds<60)return "刚刚";
 if(seconds<3600)return `${Math.floor(seconds/60)} 分钟前`;
 if(seconds<86400)return `${Math.floor(seconds/3600)} 小时前`;
 return `${Math.floor(seconds/86400)} 天前`;
}
export const routeLabels: Record<string,string> = { verified: "当前验证通过", disabled: "已停用", "temporarily-suspended": "临时停用 · 延期验证", "policy-disabled": "配额或账户策略停用", unverified: "待验证 / 验证过期" };

// Entry runtime IDs identify application instances; node IDs identify hosts.
// Resolve the explicit binding before displaying a runtime or route name.
export function hostNames(inventory: { nodes: { id: string; name: string }[]; endpoints: { entryId: string; nodeId: string }[] }) {
 const hosts = new Map(inventory.nodes.map(node => [node.id, node.name]));
 const names = new Map(hosts);
 for (const endpoint of inventory.endpoints) names.set(endpoint.entryId, hosts.get(endpoint.nodeId) ?? endpoint.entryId);
 return names;
}
