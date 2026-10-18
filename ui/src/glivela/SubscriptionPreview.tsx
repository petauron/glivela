import { useEffect, useState } from "react";
import { APIError } from "@/api";
import type { Language } from "@/translations";
import { Button } from "@/components/ui/button";
import { copy } from "@/views/shared";
import { RouteHealth } from "./RouteHealth";

type Exclusion = { endpointId: string; routeId?: string; name: string; protocol?: string; reason: string };
export type SubscriptionPreviewView = {
  accountId: string; source: string; reason?: string; appliedRevision: number;
  checkedAt: string; fingerprint: string; count: number;
  items: Array<{ name: string; protocol: string }>; excluded: Exclusion[];
};
const reasons: Record<string, [string, string]> = {
  account_disabled: ["账号已停用", "Account disabled"], account_expired: ["账号已到期", "Account expired"],
  account_pending: ["账号配置尚未应用", "Account configuration pending"], quota_exhausted: ["账号流量已用尽", "Account quota exhausted"],
  entry_quota_exhausted: ["入口流量额度未启用或已用尽", "Entry quota unavailable or exhausted"],
  publication_pending: ["公网入口未就绪或发布修订尚未应用", "Public entry not ready or publication pending"],
  entry_pending: ["入口运行状态或配置修订未就绪", "Entry runtime or configuration pending"],
  credential_disabled: ["此账号的入口凭据已停用", "Entry credential disabled for this account"], protocol_disabled: ["入口协议已停用", "Entry protocols disabled"],
  route_protocol_disabled: ["此入口未启用 VLESS 双跳协议", "VLESS routing is not enabled on this entry"],
  route_revoked: ["线路已停用或正在撤权", "Route disabled or revoking"], landing_unavailable: ["落地服务未就绪", "Exit service unavailable"],
  landing_offline: ["落地节点离线或身份不可用", "Exit node offline or identity unavailable"], health_expired: ["线路验证已过期", "Route verification expired"],
  configuration_pending: ["配置或链路验证尚未就绪", "Configuration or verification pending"], authorization_unavailable: ["落地授权尚未就绪", "Exit authorization unavailable"],
  native_unavailable: ["直连已撤销、停用或不再满足发布条件", "Direct entry removed, disabled or no longer publishable"],
  native_hidden: ["按线路配置隐藏直连，不自动回退直出", "Direct entry hidden by route configuration; no automatic direct fallback"],
  route_unavailable: ["历史线路未通过当前授权或健康检查", "Historical route failed current authorization or health checks"],
  subscription_unavailable: ["当前没有可提供的有效订阅", "No valid subscription is currently available"],
};
function reason(language: Language, code: string) {
  const text = reasons[code];
  return text ? copy(language, text[0], text[1]) : copy(language, "无法确认原因，请查看线路配置", "Reason unavailable; inspect route configuration");
}
export function SubscriptionPreview({ accountId, language, onInspectEndpoint }: { accountId: string; language: Language; onInspectEndpoint: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<SubscriptionPreviewView | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    const deadline = window.setTimeout(() => controller.abort(), 15000);
    let active = true;
    setView(null); setError(""); setBusy(true);
    void (async () => {
      const response = await fetch(`/api/v1/meridian/accounts/${encodeURIComponent(accountId)}/subscription-preview`, { credentials: "same-origin", cache: "no-store", signal: controller.signal });
      if (!response.ok) throw new APIError("Subscription preview unavailable", response.status);
      const next = await response.json() as SubscriptionPreviewView;
      if (active) setView(next);
    })().catch((cause) => {
      if (!active) return;
      const message = controller.signal.aborted ? copy(language, "读取超时，请重试。", "Read timed out. Retry.")
        : cause instanceof APIError && cause.status === 401 ? copy(language, "登录已失效，请重新登录后重试。", "Your session expired. Sign in again and retry.")
        : cause instanceof APIError && cause.status === 404 ? copy(language, "账号已不存在，请刷新账号列表。", "This account no longer exists. Refresh the account list.")
        : copy(language, "暂时无法读取订阅预览，请检查连接后重试。", "Subscription preview is temporarily unavailable. Check the connection and retry.");
      setError(message);
    })
      .finally(() => { window.clearTimeout(deadline); if (active) setBusy(false); });
    return () => { active = false; window.clearTimeout(deadline); controller.abort(); };
  }, [open, accountId, refresh, language]);
  const source = view?.source === "live" ? copy(language, "实时结果", "Live result") : view?.source === "applied_snapshot" ? copy(language, "已应用快照", "Applied snapshot") : view?.source === "imported_snapshot" ? copy(language, "迁移快照", "Imported snapshot") : copy(language, "当前不可用", "Unavailable");
  return <details className="mt-3 border-t pt-3 text-sm" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary className="w-fit cursor-pointer">{copy(language, "预览订阅", "Preview subscription")}</summary>
    {open ? <div className="mt-3 flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">{copy(language, "与实际下载使用同一清单；不显示订阅令牌或连接凭据。状态变化后请刷新。", "Uses the actual download inventory without tokens or connection credentials. Refresh after state changes.")}</p>
      <Button size="sm" variant="outline" className="self-start" disabled={busy} onClick={() => setRefresh((value) => value + 1)}>{copy(language, "刷新预览", "Refresh preview")}</Button>
      {busy ? <p role="status">{copy(language, "正在读取订阅…", "Reading subscription…")}</p> : null}
      {error ? <p role="alert" className="text-destructive">{error}</p> : null}
      {view ? <>
        <p role="status">{copy(language, `实际可订阅 ${view.count} 条`, `${view.count} published entries`)} · {source}</p>
        <p className="text-xs text-muted-foreground">{copy(language, "读取时间", "Read at")} {new Date(view.checkedAt).toLocaleString(language)} · {copy(language, "账号应用修订", "Applied account revision")} {view.appliedRevision}</p>
        {view.reason ? <p className="text-destructive">{reason(language, view.reason)}</p> : null}
        <ul className="divide-y">{view.items.map((item) => <li className="flex flex-wrap justify-between gap-2 py-2" key={`${item.protocol}:${item.name}`}><span>{item.name}</span><span className="text-muted-foreground">{item.protocol}</span></li>)}</ul>
        {view.excluded.length ? <section aria-label={copy(language, "未纳入订阅", "Excluded from subscription")}><h4 className="font-medium">{copy(language, "未纳入订阅", "Excluded from subscription")}</h4><ul className="divide-y">{view.excluded.map((item) => <li className="flex flex-col gap-2 py-3" key={`${item.endpointId}:${item.routeId ?? ""}:${item.protocol ?? ""}:${item.reason}:${item.name}`}><p>{item.name}{item.protocol ? ` · ${item.protocol}` : ""} · {reason(language, item.reason)}</p>{item.endpointId ? <Button size="sm" variant="ghost" className="self-start" onClick={() => onInspectEndpoint(item.endpointId)}>{copy(language, "查看入口配置", "Inspect entry configuration")}</Button> : null}{item.routeId ? <RouteHealth routeId={item.routeId} language={language} primaryName={copy(language, "主落地", "Primary exit")} ipv4Name={copy(language, "IPv4 落地", "IPv4 exit")} /> : null}</li>)}</ul></section> : null}
      </> : null}
    </div> : null}
  </details>;
}
