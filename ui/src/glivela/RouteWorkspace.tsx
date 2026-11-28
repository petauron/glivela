import { useState } from "react";
import { Search, X, MoreHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { LatencyCell, latencyKey, type RouteLatency } from "./RouteLatency";
import { LinkSpeed, RouteSpeedSummary, speedKey, useLinkSpeed, type SpeedBody, type SpeedList } from "./LinkSpeed";
import { isSuspensionActive, routeLabels } from "./control-format";
import type { Inventory, Route } from "./control-types";
import { PathMTU } from "./PathMTU";
import {
  buildRouteChangePayload,
  formatSampleAge,
  summarizePooledRoute,
  type PooledRouteSummary,
} from "./relay-pool-model";

function PooledLatencyCell({ summary }: { summary: PooledRouteSummary }) {
  if (summary.blockedByEmptyPool) {
    return (
      <span className="gl-status" data-tone="warning" title="中转池内没有已准入的可用候选，线路按 Fail-Closed 阻断，不回退直连。">
        池空阻断
      </span>
    );
  }
  if (summary.bestDelayMs != null) {
    return (
      <div className="gl-pooled-telemetry-cell" title="入口 burstObservatory 完整路径采样（低频，非直连 TCP 1080 延迟）。">
        <span className="gl-latency-value" data-tone={summary.bestDelayMs > 100 ? "slow" : "fast"}>
          {summary.bestDelayMs} ms
        </span>
        <small className="gl-secondary">
          {summary.healthyCount}/{summary.admittedCount} 健康
          {summary.staleCount > 0 ? ` · ${summary.staleCount} 过期` : ""}
        </small>
      </div>
    );
  }
  if (summary.unhealthyCount > 0) {
    return (
      <span className="gl-status" data-tone="warning">
        探测失败 ({summary.unhealthyCount}/{summary.admittedCount})
      </span>
    );
  }
  if (summary.staleCount > 0) {
    return (
      <span className="gl-status" data-tone="warning">
        样本过期 ({summary.staleCount})
      </span>
    );
  }
  return <span className="gl-secondary">尚无观测样本</span>;
}

export function RouteWorkspace({
  inventory,
  names,
  disabled,
  save,
  latency,
  loadSpeeds,
  active,
}: {
  inventory: Inventory;
  names: Map<string, string>;
  disabled: boolean;
  save: (operation: string, body: unknown) => Promise<boolean>;
  latency: { values: Map<string, RouteLatency>; now: number; busy: boolean; error: string; refresh: (force?: boolean) => Promise<void> };
  loadSpeeds: (body: SpeedBody, signal?: AbortSignal) => Promise<SpeedList>;
  active: boolean;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState("");
  const [deleteKey, setDeleteKey] = useState("");
  const speed = useLinkSpeed(loadSpeeds, active);
  const rows = inventory.routes;
  const poolsById = new Map((inventory.relayPools ?? []).map((p) => [p.id, p]));
  const nodeName = (id: string) => names.get(id) ?? id;
  const poolName = (id?: string) => (id ? poolsById.get(id)?.name ?? id : "");
  const label = (row: Route) => `${nodeName(row.entryId)} → ${nodeName(row.egressId)}`;
  const accountName = (id: string) => inventory.accounts.find((a) => a.account.id === id)?.account.displayName ?? id;
  const landingIds = (row: Route) => [...new Set([row.egressId, row.ipv4EgressId].filter((id): id is string => !!id))];
  const isThreeHop = (row: Route) => !!row.relayId || !!row.relayPoolId;
  const routeLatency = (row: Route, landingId: string) =>
    isThreeHop(row) ? undefined : latency.values.get(latencyKey(row.entryId, landingId, landingId === row.ipv4EgressId ? row.ipv4Port ?? 0 : row.port));
  const state = (row: Route) => routeLabels[row.state] ?? "未确认";
  const paused = (id: string) => isSuspensionActive(inventory.availability?.nodes[id], latency.now);
  const pooledSummary = (row: Route) => (row.relayPoolId ? summarizePooledRoute(row, inventory, latency.now) : undefined);

  const listState = (row: Route) => {
    if (!row.enabled) return { enabled: false, detail: "线路开关已关闭。" };
    const account = inventory.accounts.find((item) => item.account.id === row.accountId);
    if (account && !account.account.plan.enabled) return { enabled: false, detail: "账户已停用，线路开关仍为启用。" };
    if (row.state === "policy-disabled") return { enabled: false, detail: "账户额度或策略限制了此线路，线路开关仍为启用。" };
    if (row.state === "temporarily-suspended" || landingIds(row).some(paused) || paused(row.entryId) || (!!row.relayId && paused(row.relayId))) {
      return { enabled: false, detail: "相关入口、中转或落地暂时停用，线路开关仍为启用。" };
    }
    if (row.relayPoolId) {
      const admitted = row.activeRelayIds ? row.activeRelayIds.length : row.activeRelays ?? 0;
      if (admitted === 0) {
        return {
          enabled: false,
          label: "池空阻断",
          tone: "warning" as const,
          detail: "中转池当前没有已准入的可用中转，线路按 Fail-Closed 阻断，不会回退直连。",
        };
      }
      if (!inventory.runtimes.some((node) => node.id === row.entryId && node.runtimeReady)) {
        return {
          enabled: false,
          label: "未确认",
          detail: "线路已配置中转池，但入口尚未上报当前修订的应用回执。",
        };
      }
      return {
        enabled: true,
        detail: `线路已启用，当前有 ${admitted} 个已准入中转候选；实际健康与延迟以入口 burstObservatory 采样为准。`,
      };
    }
    if (row.relayId && [row.entryId, row.relayId, row.egressId].some((id) => !inventory.runtimes.some((node) => node.id === id && node.runtimeReady))) {
      return { enabled: false, label: "未确认", detail: "线路开关已启用，但入口、中转或落地尚未确认当前配置；请检查节点状态。" };
    }
    return { enabled: true, detail: "线路已启用；实际连通性以检测结果为准。" };
  };

  const shown = rows.filter(
    (row) =>
      (filter === "all" || (filter === "enabled" ? listState(row).enabled : !listState(row).enabled)) &&
      `${label(row)} ${row.name ?? ""} ${nodeName(row.entryId)} ${row.relayId ? nodeName(row.relayId) : ""} ${poolName(row.relayPoolId)} ${poolName(row.pendingRelayPoolId)} ${landingIds(row).map(nodeName).join(" ")} ${accountName(row.accountId)}`
        .toLocaleLowerCase()
        .includes(query.toLocaleLowerCase()),
  );
  const groups = new Map<string, Route[]>();
  for (const row of shown) groups.set(row.entryId, [...(groups.get(row.entryId) ?? []), row]);
  const itemKey = (row: Route, landingId: string) => `server/${row.id}/${landingId}`;
  const current = shown.find((row) => landingIds(row).some((landingId) => itemKey(row, landingId) === selected));
  const currentPooled = current ? pooledSummary(current) : undefined;

  const reason = (row: Route, landingId: string) => {
    if (!row.enabled) return "该线路已停用。";
    if (isThreeHop(row)) return "暂不支持三跳测速。";
    if (!listState(row).enabled) return listState(row).detail;
    const authorized = inventory.routes.some(
      (route) =>
        route.enabled &&
        !["disabled", "temporarily-suspended", "policy-disabled"].includes(route.state) &&
        route.entryId === row.entryId &&
        (route.egressId === landingId || route.ipv4EgressId === landingId),
    );
    if (!authorized || row.entryId === landingId) return "该入口与落地配对未启用测速。";
    const ready = new Set(inventory.runtimes.filter((node) => node.runtimeReady).map((node) => node.id));
    if (!ready.has(row.entryId) || !ready.has(landingId)) return "两端节点就绪后可测速。";
    const measured = routeLatency(row, landingId);
    if (measured?.latencyMs != null && measured.latencyMs > 100) return "线路参考延迟超过 100ms，无法开始测速。";
    return "";
  };

  const toggle = (row: Route) => {
    const account = inventory.accounts.find((a) => a.account.id === row.accountId);
    if (!account) return;
    void save("routes", buildRouteChangePayload(row, { enabled: !row.enabled, expectedRevision: account.account.desiredRevision }));
  };
  const toggleUDP = (row: Route) => {
    const account = inventory.accounts.find((a) => a.account.id === row.accountId);
    if (!account) return;
    void save("routes", buildRouteChangePayload(row, { udp: !row.udp, expectedRevision: account.account.desiredRevision }));
  };
  const toggleHideNative = (row: Route) => {
    const account = inventory.accounts.find((a) => a.account.id === row.accountId);
    if (!account) return;
    void save("routes", buildRouteChangePayload(row, { hideNative: !row.hideNative, expectedRevision: account.account.desiredRevision }));
  };
  const hiddenBySibling = (row: Route) =>
    inventory.routes.some(
      (other) => other.id !== row.id && other.accountId === row.accountId && other.entryId === row.entryId && other.enabled && other.hideNative,
    );
  const remove = async (row: Route) => {
    const account = inventory.accounts.find((a) => a.account.id === row.accountId);
    if (!account || row.enabled) return;
    const ok = await save("routes", buildRouteChangePayload(row, { enabled: false, delete: true, expectedRevision: account.account.desiredRevision }));
    if (ok) {
      setDeleteKey("");
      setSelected("");
    }
  };

  return (
    <div className="gl-split gl-route-split">
      <div className="gl-primary">
        <div className="gl-toolbar gl-route-toolbar">
          <label className="gl-search">
            <Search />
            <input aria-label="搜索线路" placeholder="搜索入口、中转池、落地或账户…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <div className="gl-segment" role="group" aria-label="按线路状态筛选" title="启用表示线路开关和已知限制状态，实际连通性以检测结果为准。">
            {[
              ["all", "全部"],
              ["enabled", "启用"],
              ["disabled", "停用"],
            ].map(([id, text]) => (
              <button key={id} aria-pressed={filter === id} onClick={() => setFilter(id)}>
                {text}
              </button>
            ))}
          </div>
        </div>
        {latency.error ? (
          <p role="status" className="gl-inline-error">
            {latency.error}
          </p>
        ) : null}
        {[...latency.values.values()].some((value) => value.historyUnavailable) ? (
          <p role="status" className="gl-inline-error">
            延迟历史暂时无法保存，重启后可能丢失；当前检测不受影响。
          </p>
        ) : null}
        {speed.connectionError ? (
          <p role="status" className="gl-inline-error">
            测速结果暂时无法更新：{speed.connectionError}
          </p>
        ) : null}
        <div className="gl-table-scroll">
          <table className="gl-data-table gl-routes">
            <thead>
              <tr>
                <th>线路</th>
                <th>TCP 延迟 / 探活</th>
                <th>线路测速</th>
                <th>
                  <span className="sr-only">详情</span>
                </th>
              </tr>
            </thead>
            {[...groups].map(([entryId, group]) => (
              <tbody key={entryId}>
                <tr className="gl-route-group">
                  <th colSpan={4} scope="rowgroup">
                    入口 · {nodeName(entryId)} <span>{group.length} 组</span>
                  </th>
                </tr>
                {group.flatMap((row) =>
                  landingIds(row).map((landingId, index) => {
                    const status = listState(row);
                    const summary = pooledSummary(row);
                    const name = nodeName(landingId);
                    const meta = [
                      row.relayPoolId
                        ? `经池 ${poolName(row.relayPoolId)} (${summary?.admittedCount ?? 0}/${summary?.totalMembers ?? 0})`
                        : row.relayId
                          ? `经 ${nodeName(row.relayId)}`
                          : "",
                      row.pendingLegacyCutover ? `待切池 ${poolName(row.pendingRelayPoolId)}` : "",
                      row.retiringLegacyTransport ? "旧三跳退场中" : "",
                      row.name ?? "",
                      row.hideNative ? (row.enabled ? "隐藏直连" : "已设隐藏直连") : "",
                      inventory.accounts.length > 1 ? accountName(row.accountId) : "",
                    ]
                      .filter(Boolean)
                      .join(" · ");
                    return (
                      <tr key={itemKey(row, landingId)} data-selected={selected === itemKey(row, landingId)} onClick={() => setSelected(itemKey(row, landingId))}>
                        <td>
                          <div className="gl-route-heading">
                            <span className="gl-status" data-tone={status.tone ?? (status.enabled ? "good" : "muted")} title={status.detail}>
                              {status.label ?? (status.enabled ? "启用" : "停用")}
                            </span>
                            <div className="gl-route-label">
                              <button className="gl-route-name" title={name} aria-label={name} onClick={() => setSelected(itemKey(row, landingId))}>
                                {name}
                              </button>
                              {meta ? (
                                <small className="gl-route-meta" title={meta}>
                                  {meta}
                                </small>
                              ) : null}
                            </div>
                          </div>
                        </td>
                        <td>
                          {summary ? (
                            <PooledLatencyCell summary={summary} />
                          ) : (
                            <LatencyCell hideEmpty value={routeLatency(row, landingId)} now={latency.now} failed={!!latency.error} />
                          )}
                        </td>
                        <td>
                          {row.relayPoolId ? (
                            <span className="gl-secondary">池化三跳</span>
                          ) : row.relayId ? (
                            "—"
                          ) : (
                            <RouteSpeedSummary test={speed.latest.get(speedKey(row.entryId, landingId))} />
                          )}
                        </td>
                        <td>
                          <button
                            className="gl-icon-button"
                            aria-label={`查看 ${label(row)}${index > 0 ? ` · IPv4 ${nodeName(landingId)}` : ""} 线路详情`}
                            onClick={() => setSelected(itemKey(row, landingId))}
                          >
                            <MoreHorizontal />
                          </button>
                        </td>
                      </tr>
                    );
                  }),
                )}
              </tbody>
            ))}
          </table>
          {!shown.length ? (
            <div className="gl-empty">
              <Search />
              <h3>没有匹配的线路</h3>
              <p>切换筛选条件，或新增一条已授权的组合。</p>
            </div>
          ) : null}
        </div>
      </div>

      {current ? (
        <aside className="gl-inspector" data-mobile-open="true" aria-label="线路详情">
          <header>
            <h2>线路详情</h2>
            <button className="gl-icon-button" aria-label="关闭线路详情" onClick={() => setSelected("")}>
              <X />
            </button>
          </header>
          <div className="gl-route-definitions">
            {[
              ["入口", nodeName(current.entryId)],
              ...(current.relayPoolId
                ? [
                    ["中转池", poolName(current.relayPoolId)],
                    ["已准入候选", `${currentPooled?.admittedCount ?? 0} / ${currentPooled?.totalMembers ?? 0}`],
                  ]
                : current.relayId
                  ? [["中转", nodeName(current.relayId)]]
                  : []),
              ["落地", nodeName(current.egressId)],
              ...(current.ipv4EgressId ? [["IPv4 落地", nodeName(current.ipv4EgressId)]] : []),
              ...(current.landingAddress ? [["落地地址", `${current.landingAddress}:${current.port || 24000}`]] : []),
              ...(current.egressIp ? [["指定出口", current.egressIp]] : []),
              ...(current.ingressFamily ? [["入中转地址族", current.ingressFamily.toUpperCase()]] : []),
              ["账户", accountName(current.accountId)],
              [
                "入口直连",
                current.hideNative
                  ? current.enabled
                    ? "已隐藏"
                    : hiddenBySibling(current)
                      ? "由他线隐藏"
                      : "已设隐藏"
                  : hiddenBySibling(current)
                    ? "由他线隐藏"
                    : "已保留",
              ],
              ["状态", listState(current).label ?? (listState(current).enabled ? "启用" : "停用")],
            ].map(([title, value]) => (
              <div key={title}>
                <h3>{title}</h3>
                <p title={value}>{value}</p>
              </div>
            ))}
          </div>
          <p className="gl-context-copy">{listState(current).detail}</p>
          <p className="gl-context-copy">{current.udp ? "UDP 已配置，节点应用后写入订阅；请刷新订阅。" : "UDP 未启用。"} UDP 443 保持阻断。</p>
          <p className="gl-context-copy">
            {current.hideNative
              ? current.enabled
                ? "订阅中已隐藏此入口的 VLESS 直连节点，保留身份与历史流量；修改后请刷新订阅。"
                : hiddenBySibling(current)
                  ? "此线路已设隐藏且当前停用，但同入口另有启用中的转发线路隐藏了 VLESS 直连。"
                  : "已设置隐藏此入口的 VLESS 直连；重新启用该线路后生效，保留身份与历史流量。"
              : hiddenBySibling(current)
                ? "此线路未设置隐藏直连，但同入口另有启用中的转发线路隐藏了 VLESS 直连；需全部关闭隐藏后才会恢复显示。"
                : "订阅中同时保留此入口的直连节点。"}
          </p>

          {current.pendingLegacyCutover ? (
            <section>
              <h3>旧三跳迁移切换</h3>
              <p className="gl-context-copy">
                该线路当前仍保留传统单中转运行，已关联目标中转池「{poolName(current.pendingRelayPoolId)}」。待中转与落地均上报 EIH 24000 回执后，可显式切换至中转池。
              </p>
              <Button
                className="gl-wide"
                variant="outline"
                disabled={disabled}
                onClick={() => void save("socket-cutover", { action: "cutover-legacy", grantId: current.id })}
              >
                切换至中转池
              </Button>
            </section>
          ) : null}

          <details className="gl-context-details gl-route-verification">
            <summary>查看验证信息</summary>
            <p>{state(current)}</p>
          </details>

          {currentPooled ? (
            <section className="gl-route-latencies">
              <h3>完整路径探活采样（burstObservatory）</h3>
              <p className="gl-context-copy">
                区分期望配置、节点回执与入口低频采样；采样异常不会触发节点重启或配置重载。
              </p>
              {currentPooled.paths.length === 0 ? (
                <p className="gl-context-copy">关联中转池当前没有成员（Fail-Closed 阻断）。</p>
              ) : (
                <ul className="gl-route-pool-paths">
                  {currentPooled.paths.map((path) => (
                    <li key={path.id} className="gl-route-pool-path-item">
                      <div>
                        <strong>
                          #{path.memberOrder} {nodeName(path.relayNodeId)}
                        </strong>
                        <small className="gl-route-meta">
                          回执：{path.admitted ? "已准入" : path.memberDrained ? "已排空" : path.nodeSuspended ? "节点停用" : "未准入"}
                        </small>
                      </div>
                      <div className="gl-route-pool-path-metric">
                        {path.telemetry.state === "healthy" ? (
                          <span className="gl-latency-value" data-tone={(path.telemetry.delayMs ?? 0) > 100 ? "slow" : "fast"}>
                            {path.telemetry.delayMs} ms
                          </span>
                        ) : path.telemetry.state === "unhealthy" ? (
                          <span className="gl-latency-value" data-tone="failure">
                            失败
                          </span>
                        ) : path.telemetry.state === "stale" ? (
                          <span className="gl-latency-value" data-tone="muted">
                            样本过期
                          </span>
                        ) : (
                          <span className="gl-secondary">尚无样本</span>
                        )}
                        <small className="gl-route-meta">
                          {path.telemetry.sampledAt ? formatSampleAge(path.telemetry.sampledAt, latency.now) : "—"}
                          {path.telemetry.allSamples > 0 ? ` · ${path.telemetry.failedSamples}/${path.telemetry.allSamples} 失败` : ""}
                        </small>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ) : current.relayId ? (
            <p className="gl-context-copy">三跳线路暂不显示直连测速或 MTU 结果；请通过客户端验证。</p>
          ) : (
            <>
              <section className="gl-route-latencies">
                <h3>TCP 连接记录</h3>
                {landingIds(current).map((landingId) => (
                  <div className="gl-route-latency-detail" key={landingId}>
                    <p>{nodeName(landingId)}</p>
                    <LatencyCell value={routeLatency(current, landingId)} now={latency.now} failed={!!latency.error} />
                  </div>
                ))}
              </section>
              {landingIds(current).map((landingId) => (
                <PathMTU
                  key={`mtu/server/${current.id}/${landingId}`}
                  routeId={current.id}
                  mode="server"
                  landingId={landingId}
                  landingName={nodeName(landingId)}
                  disabled={disabled}
                />
              ))}
              {landingIds(current).map((landingId) => (
                <LinkSpeed
                  key={`${current.id}/${landingId}`}
                  entryId={current.entryId}
                  entryName={nodeName(current.entryId)}
                  landingId={landingId}
                  landingName={nodeName(landingId)}
                  reason={reason(current, landingId)}
                  disabled={disabled}
                  control={speed}
                />
              ))}
            </>
          )}

          <section>
            <Button
              className="gl-wide"
              variant="outline"
              disabled={disabled || !inventory.accounts.some((a) => a.account.id === current.accountId)}
              onClick={() => toggleUDP(current)}
            >
              {current.udp ? "停用 UDP" : "启用 UDP"}
            </Button>
            <Button
              className="gl-wide"
              variant="outline"
              disabled={disabled || !inventory.accounts.some((a) => a.account.id === current.accountId)}
              onClick={() => toggleHideNative(current)}
            >
              {current.hideNative ? "显示入口直连" : "隐藏入口直连"}
            </Button>
            <Button
              className="gl-wide"
              variant="outline"
              disabled={disabled || !inventory.accounts.some((a) => a.account.id === current.accountId)}
              onClick={() => toggle(current)}
            >
              {current.enabled ? (listState(current).enabled ? "停用线路" : "关闭线路开关") : "启用线路"}
            </Button>
            {deleteKey === selected ? (
              <div className="gl-route-delete-confirm" role="group" aria-label="确认删除线路">
                <p>
                  删除后线路将从列表和新订阅中移除，历史流量保留。{current.ipv4EgressId ? "这条线路的两个落地会一并删除。" : ""}
                </p>
                <div>
                  <Button variant="outline" disabled={disabled} onClick={() => setDeleteKey("")}>
                    取消
                  </Button>
                  <Button variant="destructive" disabled={disabled || current.enabled} onClick={() => void remove(current)}>
                    确认删除
                  </Button>
                </div>
              </div>
            ) : (
              <Button className="gl-wide gl-route-delete-button" variant="ghost" disabled={disabled || current.enabled} onClick={() => setDeleteKey(selected)}>
                删除线路
              </Button>
            )}
            {current.enabled ? <p className="gl-route-delete-hint">请先停用线路，待节点应用后再删除。</p> : null}
          </section>
        </aside>
      ) : null}
    </div>
  );
}
