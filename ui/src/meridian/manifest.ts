// Glivela owns its navigation. Center only supplies the mount point.
export const manifest = {
  appKey: "vastora-official/meridian",
  pages: [
    { id: "nodes", title: { "zh-CN": "节点概览", en: "Nodes" }, surface: "tab" },
    { id: "network", title: { "zh-CN": "线路测速", en: "Link tests" }, surface: "tab" },
    { id: "traffic", title: { "zh-CN": "流量用量", en: "Traffic" }, surface: "tab" },
    { id: "accounts", title: { "zh-CN": "账号与订阅", en: "Accounts & subscriptions" }, surface: "manager" },
  ],
} as const;
