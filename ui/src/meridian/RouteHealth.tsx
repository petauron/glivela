import { useEffect, useState } from "react";
import { APIError } from "@/api";
import type { Language } from "@/translations";
import { Button } from "@/components/ui/button";
import { StateBadge, copy, userError } from "@/views/shared";

type HealthLeg = {
  role: string; state: string; linkState: string; stage: string; reason: string;
  durationMs: number; httpStatus?: number; exitFamily?: number;
  startedAt?: string; checkedAt?: string; lastHealthyAt?: string; allowedUntil?: string;
};
type Health = { status: string; reason: string; receivedAt?: string; observedAt?: string; legs: HealthLeg[] };
type HealthView = { current: Health; history: Health[]; checkedAt: string };

const labels: Record<string, [string, string]> = {
  verified: ["验证通过", "Verified"], transport_unverified: ["链路未通过验证", "Transport not verified"],
  evidence_expired: ["验证结果过期，等待新上报", "Evidence expired; awaiting a fresh report"],
  authorization_unavailable: ["权限或落地配置未就绪", "Authorization or egress configuration unavailable"],
  configuration_pending: ["配置正在变化，等待验证", "Configuration pending verification"],
  exit_family_mismatch: ["出口 IP 类型与配置不符", "Exit address family mismatch"],
  private_link_before: ["私网直连（检测前）", "Private link before probe"],
  private_link_after: ["私网直连（检测后）", "Private link after probe"],
  business_check: ["代理业务检测", "Proxy exchange"], socks_connect: ["SOCKS TCP 连接", "SOCKS TCP connection"],
  socks_handshake: ["SOCKS 握手", "SOCKS negotiation"], tls_handshake: ["TLS 握手", "TLS handshake"],
  http_response: ["HTTP 响应", "HTTP response"], http_body: ["HTTP 响应读取", "HTTP body read"], exit_address: ["公网出口解析", "Public exit parsing"],
  gate: ["安全门禁", "Traffic gate"], verification: ["验证结果核对", "Evidence validation"], complete: ["全部完成", "Complete"],
  direct: ["直连", "Direct"], derp: ["DERP 中继", "DERP relay"], peer_relay: ["节点中继", "Peer relay"], disconnected: ["私网断开", "Private network disconnected"],
  timeout: ["超时", "Timeout"], canceled: ["检测取消", "Probe canceled"], connection_refused: ["连接被拒绝", "Connection refused"],
  connection_reset: ["连接被重置", "Connection reset"], connection_closed: ["连接提前关闭", "Connection closed"],
  certificate_verification: ["证书验证失败", "Certificate verification failed"], unexpected_http_status: ["HTTP 返回异常状态", "Unexpected HTTP status"],
  direct_and_business_ready: ["直连与 HTTPS 均通过", "Direct link and HTTPS verified"], renewal_failed: ["门禁续期失败", "Gate renewal failed"],
  evidence_invalid_or_expired: ["验证结果无效或过期", "Evidence invalid or expired"], fresh_disco_direct_response: ["收到最新直连响应", "Fresh direct response"],
  peer_identity_mismatch: ["私网节点身份不匹配", "Peer identity mismatch"], peer_identity_changed: ["检测期间身份变化", "Peer identity changed during probe"],
  invalid_peer_identity: ["私网身份记录无效", "Invalid private identity"], local_target_is_not_remote: ["检测目标指向本机", "Probe target is local"],
  peer_disconnected: ["落地私网离线", "Egress peer offline"], private_network_disconnected: ["本机私网断开", "Local private network disconnected"],
  local_status_unavailable: ["无法读取私网状态", "Private status unavailable"], probe_failed: ["私网探测失败", "Private probe failed"],
  probe_expired: ["私网探测超时", "Private probe expired"], derp_detected: ["检测到 DERP 中继", "DERP relay detected"], peer_relay_detected: ["检测到节点中继", "Peer relay detected"],
  direct_endpoint_unavailable: ["直连端点不可用", "Direct endpoint unavailable"], probe_target_mismatch: ["检测目标不匹配", "Probe target mismatch"],
  monitor_starting: ["验证刚启动", "Monitor starting"], monitor_stopped: ["验证已停止", "Monitor stopped"],
  check_failed: ["检测失败，原因未分类", "Unclassified check failure"], unreported: ["尚无检测信息", "Not reported"], disabled: ["线路已禁用", "Route disabled"],
};
function label(language: Language, code: string) {
  const value = labels[code];
  return value ? copy(language, value[0], value[1]) : copy(language, "未知原因", "Unknown reason");
}
function date(language: Language, value?: string) {
  const parsed = value ? new Date(value) : null;
  return parsed && Number.isFinite(parsed.getTime()) && parsed.getUTCFullYear() > 1970 ? parsed.toLocaleString(language) : "—";
}

export function RouteHealth({ routeId, language, primaryName, ipv4Name }: { routeId: string; language: Language; primaryName: string; ipv4Name?: string }) {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<HealthView | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  // Load only an expanded route, without a per-row background polling loop.
  // This read-only endpoint uses the existing Center session; no probe or task
  // is launched, and aborting a closed panel prevents stale response updates.
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setBusy(true); setError(""); setView(null);
    void (async () => {
      const response = await fetch(`/api/v1/meridian/routes/${encodeURIComponent(routeId)}/health`, { credentials: "same-origin", signal: controller.signal });
      const body = await response.json();
      if (!response.ok) throw new APIError(body.error ?? "Route health unavailable", response.status);
      if (!controller.signal.aborted) setView(body as HealthView);
    })().catch((cause) => { if (!controller.signal.aborted) setError(userError(language, cause)); })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [open, routeId, revision, language]);
  return <details className="text-xs" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary className="w-fit cursor-pointer text-muted-foreground">{copy(language, "健康验证详情", "Health verification details")}</summary>
    {open ? <div className="mt-2 flex min-w-0 flex-col gap-3">
      <Button size="sm" variant="outline" className="self-start" disabled={busy} onClick={() => setRevision((value) => value + 1)}>{copy(language, "刷新诊断", "Refresh diagnostics")}</Button>
      {busy ? <p role="status">{copy(language, "正在读取诊断…", "Reading diagnostics…")}</p> : null}
      {error ? <p role="alert" className="text-destructive">{error}</p> : null}
      {view ? <>
        <p role="status">{label(language, view.current.reason)}</p>
        <p className="text-muted-foreground">{copy(language, "Center 收到上报", "Center received report")}: {date(language, view.current.receivedAt)} · {copy(language, "最近读取", "Read at")}: {date(language, view.checkedAt)}</p>
        {view.current.reason === "evidence_expired" ? <p>{copy(language, "Center 判定过期", "Center observed expiry")}: {date(language, view.current.observedAt)}</p> : null}
        {view.current.legs.map((leg) => <section className="flex flex-col gap-2" key={leg.role} aria-label={leg.role === "ipv4" ? ipv4Name : primaryName}>
          <div className="flex flex-wrap items-center gap-2"><strong>{leg.role === "ipv4" ? ipv4Name : primaryName}</strong><span>{copy(language, "上次检测", "Last probe")}</span><StateBadge language={language} value={leg.state === "healthy" ? "ready" : "blocked"} /></div>
          <p>{label(language, leg.stage)} · {label(language, leg.reason)} · {Math.max(0, leg.durationMs)} ms{leg.httpStatus ? ` · HTTP ${leg.httpStatus}` : ""}{leg.exitFamily ? ` · IPv${leg.exitFamily}` : ""}</p>
          <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div><dt className="text-muted-foreground">{copy(language, "私网路径", "Private transport")}</dt><dd>{label(language, leg.linkState)}</dd></div>
            <div><dt className="text-muted-foreground">{copy(language, "Agent 检测完成", "Agent completed probe")}</dt><dd>{date(language, leg.checkedAt)}</dd></div>
            <div><dt className="text-muted-foreground">{copy(language, "Agent 检测开始", "Agent started probe")}</dt><dd>{date(language, leg.startedAt)}</dd></div>
            <div><dt className="text-muted-foreground">{copy(language, "最近成功", "Last success")}</dt><dd>{date(language, leg.lastHealthyAt)}</dd></div>
            <div><dt className="text-muted-foreground">{copy(language, "验证有效至", "Evidence valid until")}</dt><dd>{date(language, leg.allowedUntil)}</dd></div>
          </dl>
        </section>)}
        <details><summary className="w-fit cursor-pointer">{copy(language, "状态变化历史（最近 7 天）", "State changes (last 7 days)")}</summary>
          {view.history.length ? <ol className="mt-2 flex flex-col gap-2">{view.history.map((event, index) => <li key={`${event.observedAt}-${index}`}><span>{date(language, event.observedAt)} · {label(language, event.reason)}</span>{event.legs.map((leg) => <p key={leg.role}>{leg.role === "ipv4" ? ipv4Name : primaryName} · {label(language, leg.stage)} · {label(language, leg.reason)}{leg.httpStatus ? ` · HTTP ${leg.httpStatus}` : ""}</p>)}</li>)}</ol> : <p role="status">{copy(language, "尚无状态变化记录。", "No recorded state changes.")}</p>}
        </details>
      </> : null}
    </div> : null}
  </details>;
}
