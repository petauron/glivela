import { useMemo, useState, type KeyboardEvent } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SelectControl } from "@/components/SelectControl";
import type { RouteLatency } from "./RouteLatency";
import type { Inventory, RelayPoolView, Runtime } from "./control-types";
import {
  buildTopologyModel,
  formatRevisionReceipt,
  formatSampleAge,
  isEntryPoolSelectedOrConnected,
  isLegacyEdgeSelectedOrConnected,
  isPathSelectedOrConnected,
  isTwoHopSelectedOrConnected,
  type FullPathStatus,
  type TopologyFilter,
  type TopologySelection,
} from "./relay-pool-model";

function truncateLabel(value: string, maxChars: number): string {
  return value.length > maxChars ? `${value.slice(0, maxChars - 1)}…` : value;
}

function handleSvgActivate(event: KeyboardEvent<SVGGElement>, action: () => void) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    action();
  }
}

function pathTelemetryLabel(path: FullPathStatus): string {
  if (!path.desiredRouteEnabled) return "线路停用";
  if (path.memberDrained) return "成员排空";
  if (path.nodeSuspended) return "节点停用";
  if (!path.admitted) return "待准入";
  switch (path.telemetry.state) {
    case "healthy":
      return `${path.telemetry.delayMs ?? 0}ms`;
    case "unhealthy":
      return "探测失败";
    case "stale":
      return "样本过期";
    default:
      return "无样本";
  }
}

function pathStrokeTone(path: FullPathStatus): "good" | "bad" | "warning" | "muted" {
  if (!path.desiredRouteEnabled || path.memberDrained || path.nodeSuspended) return "muted";
  if (!path.admitted) return "warning";
  switch (path.telemetry.state) {
    case "healthy":
      return "good";
    case "unhealthy":
      return "bad";
    case "stale":
      return "warning";
    default:
      return "muted";
  }
}

function twoHopTelemetryLabel(edge: {
  desiredEnabled: boolean;
  suspended: boolean;
  latencyState: string;
  latencyMs?: number;
}): string {
  if (!edge.desiredEnabled) return "已停用";
  if (edge.suspended) return "临时停用";
  switch (edge.latencyState) {
    case "ready":
    case "slow":
      return `${Math.round(edge.latencyMs ?? 0)}ms`;
    case "unreachable":
      return "不可达";
    case "stale":
      return "已过期";
    case "unavailable":
      return "离线";
    default:
      return "无样本";
  }
}

export function RelayTopology({
  inventory,
  names,
  latencies,
  now,
  latencyFailed,
  onEditPool,
  onEditEntryObservatory,
}: {
  inventory: Inventory;
  names: Map<string, string>;
  latencies: Map<string, RouteLatency>;
  now: number;
  latencyFailed: boolean;
  onEditPool?: (pool: RelayPoolView) => void;
  onEditEntryObservatory?: (entry: Runtime) => void;
}) {
  const [filter, setFilter] = useState<TopologyFilter>("all");
  const [entryFilter, setEntryFilter] = useState("__all__");
  const [selection, setSelection] = useState<TopologySelection>(null);

  const nodeName = (id: string) => names.get(id) ?? id;
  const poolName = (id?: string) => (id ? inventory.relayPools?.find((p) => p.id === id)?.name ?? id : "");
  const entryOptions = useMemo(
    () => [
      { value: "__all__", label: "全部入口" },
      ...inventory.runtimes
        .filter((rt) => rt.role === "entry")
        .map((rt) => ({ value: rt.id, label: nodeName(rt.id) })),
    ],
    [inventory.runtimes, names],
  );

  const model = useMemo(
    () =>
      buildTopologyModel({
        inventory,
        names,
        latencies,
        now,
        latencyFailed,
        filter,
        entryFilter: entryFilter === "__all__" ? undefined : entryFilter,
      }),
    [inventory, names, latencies, now, latencyFailed, filter, entryFilter],
  );

  const toggleSelection = (next: Exclude<TopologySelection, null>) => {
    setSelection((prev) => (JSON.stringify(prev) === JSON.stringify(next) ? null : next));
  };

  const selectedPaths = useMemo(
    () => model.allFullPaths.filter((path) => isPathSelectedOrConnected(selection, path)),
    [model.allFullPaths, selection],
  );
  const selectedTwoHop = useMemo(
    () => model.twoHopEdges.filter((edge) => isTwoHopSelectedOrConnected(selection, edge)),
    [model.twoHopEdges, selection],
  );
  const selectedLegacy = useMemo(
    () => model.legacyEdges.filter((edge) => isLegacyEdgeSelectedOrConnected(selection, edge)),
    [model.legacyEdges, selection],
  );

  const stats = useMemo(() => {
    let admitted = 0;
    let healthy = 0;
    let unhealthy = 0;
    let stale = 0;
    let noSample = 0;
    for (const p of model.allFullPaths) {
      if (!p.admitted) continue;
      admitted++;
      if (p.telemetry.state === "healthy") healthy++;
      else if (p.telemetry.state === "unhealthy") unhealthy++;
      else if (p.telemetry.state === "stale") stale++;
      else noSample++;
    }
    const blockedEntries = model.entryPoolEdges.filter((e) => e.blocked).length;
    return { admitted, healthy, unhealthy, stale, noSample, blockedEntries };
  }, [model.allFullPaths, model.entryPoolEdges]);

  const activeEntry = selection?.kind === "entry" ? model.entries.find((e) => e.id === selection.id) : undefined;
  const activePool = selection?.kind === "pool" ? model.pools.find((p) => p.id === selection.id) : undefined;
  const activeMember =
    selection?.kind === "member"
      ? model.pools.find((p) => p.id === selection.poolId)?.members.find((m) => m.nodeId === selection.nodeId)
      : undefined;
  const activeLegacyRelay = selection?.kind === "legacy-relay" ? model.legacyRelays.find((r) => r.id === selection.id) : undefined;
  const activeLegacyRoute = selection?.kind === "legacy-route" ? model.legacyEdges.find((e) => e.id === selection.id) : undefined;
  const activeLanding = selection?.kind === "landing" ? model.landings.find((l) => l.id === selection.id) : undefined;
  const activePath = selection?.kind === "path" ? model.allFullPaths.find((p) => p.id === selection.id) : undefined;
  const activeTwoHop = selection?.kind === "two-hop" ? model.twoHopEdges.find((e) => e.id === selection.id) : undefined;

  return (
    <section className="gl-topology-panel" aria-label="入口、中转池与固定出口三列交互拓扑">
      <header className="gl-topology-header">
        <div>
          <h2>三列交互拓扑</h2>
          <p className="gl-context-copy">
            左列入口、中列虚线框选路中转组（及待迁移旧三跳中转）、右列固定出口。两跳直连从上方走廊跨过中列，三跳经中转池展开完整路径。
          </p>
        </div>
        <div className="gl-topology-controls">
          <div className="gl-segment" role="group" aria-label="拓扑视图筛选">
            {(
              [
                ["all", "全部"],
                ["pooled", "三跳（池化/旧三跳）"],
                ["two-hop", "两跳直连"],
                ["attention", "需关注"],
              ] as const
            ).map(([id, label]) => (
              <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(id)}>
                {label}
              </button>
            ))}
          </div>
          <div className="gl-topology-entry-select">
            <SelectControl aria-label="按入口筛选拓扑" value={entryFilter} onValueChange={setEntryFilter} options={entryOptions} />
          </div>
          {selection ? (
            <Button type="button" variant="outline" onClick={() => setSelection(null)}>
              <X />
              清除选中
            </Button>
          ) : null}
        </div>
      </header>

      <div className="gl-topology-legend" role="note" aria-label="三层状态图例">
        <span>
          <strong>期望配置</strong>：线路开关、中转池成员顺序与排空策略
        </span>
        <span>
          <strong>节点回执</strong>：入口 / 中转 / 落地实际已应用修订号（R已应用/R期望）
        </span>
        <span>
          <strong>低频采样</strong>：
          <i className="gl-legend-swatch" data-tone="good" aria-hidden="true" />健康 RTT ·{" "}
          <i className="gl-legend-swatch" data-tone="bad" aria-hidden="true" />探测失败 ·{" "}
          <i className="gl-legend-swatch" data-tone="warning" aria-hidden="true" />样本过期 / 待准入 ·{" "}
          <i className="gl-legend-swatch" data-tone="muted" aria-hidden="true" />尚无样本 / 已排空
        </span>
      </div>

      {model.entries.length === 0 && model.pools.length === 0 && model.legacyRelays.length === 0 && model.landings.length === 0 ? (
        <div className="gl-empty">
          <h3>当前筛选条件下没有可展示的拓扑节点</h3>
          <p>请切换筛选条件，或先创建中转池与线路绑定。</p>
        </div>
      ) : (
        <div className="gl-topology-canvas">
          <svg
            className="gl-topology-svg"
            viewBox={`0 0 ${model.width} ${model.height}`}
            role="group"
            aria-label="入口、中转池、固定出口三列交互拓扑图"
          >
            {/* Column labels */}
            <text x={24} y={24} className="gl-topo-col-title">
              入口（Entries · {model.entries.length}）
            </text>
            <text x={368} y={24} className="gl-topo-col-title">
              选路中转组（Relay Pools · {model.pools.length}
              {model.legacyRelays.length > 0 ? ` · 旧三跳 ${model.legacyRelays.length}` : ""}）
            </text>
            <text x={792} y={24} className="gl-topo-col-title">
              固定出口（Fixed Landings · {model.landings.length}）
            </text>

            {/* Layer 1: Two-hop direct edges bridging strictly through the top corridor above middle cards */}
            <g className="gl-topo-layer-twohop" aria-label="两跳跨中列直连线路">
              {model.twoHopEdges.map((edge) => {
                const highlighted = isTwoHopSelectedOrConnected(selection, edge);
                const selected = selection?.kind === "two-hop" && selection.id === edge.id;
                const tone =
                  !edge.desiredEnabled || edge.suspended
                    ? "muted"
                    : edge.latencyState === "unreachable"
                      ? "bad"
                      : edge.latencyState === "stale" || edge.latencyState === "slow"
                        ? "warning"
                        : edge.latencyState === "ready"
                          ? "good"
                          : "muted";
                const text = twoHopTelemetryLabel(edge);
                return (
                  <g
                    key={edge.id}
                    className="gl-topo-edge-group"
                    data-edge-kind="two-hop"
                    data-tone={tone}
                    data-dimmed={!highlighted || undefined}
                    data-selected={selected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`两跳线路 ${nodeName(edge.entryId)} 直达 ${nodeName(edge.landingId)} · ${text}`}
                    onClick={() => toggleSelection({ kind: "two-hop", id: edge.id })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "two-hop", id: edge.id }))}
                  >
                    <path d={edge.d} className="gl-topo-edge-hit" />
                    <path
                      d={edge.d}
                      className="gl-topo-edge-path gl-topo-edge-twohop"
                      data-tone={tone}
                      strokeDasharray={edge.latencyState === "stale" || edge.latencyState === "no-sample" ? "5 4" : undefined}
                    />
                    <g transform={`translate(${edge.labelX}, ${edge.labelY})`}>
                      <rect x={-34} y={-10} width={68} height={18} rx={9} className="gl-topo-pill-bg" data-tone={tone} />
                      <text x={0} y={3} textAnchor="middle" className="gl-topo-pill-text" data-tone={tone}>
                        两跳 {text}
                      </text>
                    </g>
                  </g>
                );
              })}
            </g>

            {/* Layer 2: Entry -> RelayPool trunk edges */}
            <g className="gl-topo-layer-entry-pool" aria-label="入口至中转池连接">
              {model.entryPoolEdges.map((edge) => {
                const highlighted = isEntryPoolSelectedOrConnected(selection, edge, model.allFullPaths);
                const selected = selection?.kind === "pool" && selection.id === edge.poolId;
                const tone = edge.blocked ? "bad" : edge.desiredEnabledCount === 0 ? "muted" : edge.entryReady ? "accent" : "warning";
                const summaryText = edge.blocked ? "池空阻断" : `${edge.admittedRelayCount} 准入`;
                return (
                  <g
                    key={edge.id}
                    className="gl-topo-edge-group"
                    data-edge-kind="entry-pool"
                    data-tone={tone}
                    data-dimmed={!highlighted || undefined}
                    data-selected={selected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`入口 ${nodeName(edge.entryId)} 经中转池 ${poolName(edge.poolId)} · ${summaryText}`}
                    onClick={() => toggleSelection({ kind: "pool", id: edge.poolId })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "pool", id: edge.poolId }))}
                  >
                    <path d={edge.d} className="gl-topo-edge-hit" />
                    <path
                      d={edge.d}
                      className="gl-topo-edge-path"
                      data-tone={tone}
                      strokeDasharray={edge.blocked || edge.desiredEnabledCount === 0 ? "6 4" : undefined}
                    />
                    <g transform={`translate(${edge.labelX}, ${edge.labelY})`}>
                      <rect x={-30} y={-9} width={60} height={18} rx={9} className="gl-topo-pill-bg" data-tone={tone} />
                      <text x={0} y={3} textAnchor="middle" className="gl-topo-pill-text" data-tone={tone}>
                        {summaryText}
                      </text>
                    </g>
                  </g>
                );
              })}
            </g>

            {/* Layer 3: Legacy three-hop edges (Entry -> Legacy Single Relay -> Fixed Landing) */}
            <g className="gl-topo-layer-legacy" aria-label="传统三跳线路">
              {model.legacyEdges.map((edge) => {
                const highlighted = isLegacyEdgeSelectedOrConnected(selection, edge);
                const selected = selection?.kind === "legacy-route" && selection.id === edge.id;
                const tone = !edge.desiredEnabled || edge.suspended ? "muted" : edge.route.pendingLegacyCutover ? "warning" : "accent";
                const pill = edge.route.pendingLegacyCutover ? "旧三跳·待切池" : "旧三跳";
                return (
                  <g
                    key={edge.id}
                    className="gl-topo-edge-group"
                    data-edge-kind="legacy-three-hop"
                    data-tone={tone}
                    data-dimmed={!highlighted || undefined}
                    data-selected={selected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`传统三跳 ${nodeName(edge.entryId)} 经 ${nodeName(edge.relayNodeId)} 到 ${nodeName(edge.landingId)}${edge.pendingRelayPoolId ? `（待切换至 ${poolName(edge.pendingRelayPoolId)}）` : ""}`}
                    onClick={() => toggleSelection({ kind: "legacy-route", id: edge.id })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "legacy-route", id: edge.id }))}
                  >
                    <path d={edge.entryToRelayD} className="gl-topo-edge-hit" />
                    <path d={edge.relayToLandingD} className="gl-topo-edge-hit" />
                    <path d={edge.entryToRelayD} className="gl-topo-edge-path" data-tone={tone} strokeDasharray="4 3" />
                    <path d={edge.relayToLandingD} className="gl-topo-edge-path" data-tone={tone} strokeDasharray="4 3" />
                    <g transform={`translate(${edge.labelX}, ${edge.labelY})`}>
                      <rect x={-42} y={-9} width={84} height={18} rx={9} className="gl-topo-pill-bg" data-tone={tone} />
                      <text x={0} y={3} textAnchor="middle" className="gl-topo-pill-text" data-tone={tone}>
                        {pill}
                      </text>
                    </g>
                  </g>
                );
              })}
            </g>

            {/* Layer 4: Pool Member -> Fixed Landing full-path edges */}
            <g className="gl-topo-layer-pool-landing" aria-label="中转成员至固定出口完整路径">
              {model.poolLandingEdges.map((edge) => {
                const highlighted = isPathSelectedOrConnected(selection, edge.path);
                const selected = selection?.kind === "path" && selection.id === edge.id;
                const tone = pathStrokeTone(edge.path);
                const label = pathTelemetryLabel(edge.path);
                const dashed =
                  !edge.path.admitted || edge.path.telemetry.state === "stale" || edge.path.telemetry.state === "no-sample"
                    ? edge.path.telemetry.state === "stale"
                      ? "3 3"
                      : "5 4"
                    : undefined;
                const showPill = selected || selection !== null || model.poolLandingEdges.length <= 10;
                return (
                  <g
                    key={edge.id}
                    className="gl-topo-edge-group"
                    data-edge-kind="pool-landing"
                    data-path-state={edge.path.telemetry.state}
                    data-tone={tone}
                    data-dimmed={!highlighted || undefined}
                    data-selected={selected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`三跳路径 ${nodeName(edge.path.entryId)} 经 ${nodeName(edge.path.relayNodeId)} 到 ${nodeName(edge.path.egressId)} · ${label}`}
                    onClick={() => toggleSelection({ kind: "path", id: edge.id })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "path", id: edge.id }))}
                  >
                    <path d={edge.d} className="gl-topo-edge-hit" />
                    <path d={edge.d} className="gl-topo-edge-path" data-tone={tone} strokeDasharray={dashed} />
                    {showPill && highlighted ? (
                      <g transform={`translate(${edge.labelX}, ${edge.labelY})`}>
                        <rect x={-29} y={-9} width={58} height={18} rx={9} className="gl-topo-pill-bg" data-tone={tone} />
                        <text x={0} y={3} textAnchor="middle" className="gl-topo-pill-text" data-tone={tone}>
                          {label}
                        </text>
                      </g>
                    ) : null}
                  </g>
                );
              })}
            </g>

            {/* Column 1: Entry cards */}
            <g className="gl-topo-layer-entries">
              {model.entries.map((entry) => {
                const selected = selection?.kind === "entry" && selection.id === entry.id;
                const connected =
                  !selection ||
                  selected ||
                  (selection.kind === "pool" &&
                    (model.entryPoolEdges.some((e) => e.entryId === entry.id && e.poolId === selection.id) ||
                      model.legacyEdges.some((e) => e.entryId === entry.id && e.pendingRelayPoolId === selection.id))) ||
                  (selection.kind === "member" &&
                    model.allFullPaths.some((p) => p.entryId === entry.id && p.poolId === selection.poolId && p.relayNodeId === selection.nodeId)) ||
                  (selection.kind === "legacy-relay" && model.legacyEdges.some((e) => e.entryId === entry.id && e.legacyRelayNodeId === selection.id)) ||
                  (selection.kind === "legacy-route" && activeLegacyRoute?.entryId === entry.id) ||
                  (selection.kind === "landing" &&
                    (model.allFullPaths.some((p) => p.entryId === entry.id && p.egressId === selection.id) ||
                      model.twoHopEdges.some((e) => e.entryId === entry.id && e.landingId === selection.id) ||
                      model.legacyEdges.some((e) => e.entryId === entry.id && e.landingId === selection.id))) ||
                  (selection.kind === "path" && activePath?.entryId === entry.id) ||
                  (selection.kind === "two-hop" && activeTwoHop?.entryId === entry.id);
                const readyTone = entry.suspended ? "warning" : entry.runtime?.runtimeReady ? "good" : "muted";
                return (
                  <g
                    key={entry.id}
                    className="gl-topo-card"
                    data-node-kind="entry"
                    data-selected={selected || undefined}
                    data-dimmed={!connected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`入口 ${entry.name} · ${formatRevisionReceipt(entry.runtime?.revision, entry.runtime?.appliedRevision, !!entry.runtime?.runtimeReady)}`}
                    onClick={() => toggleSelection({ kind: "entry", id: entry.id })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "entry", id: entry.id }))}
                  >
                    <rect x={entry.x} y={entry.y} width={entry.width} height={entry.height} rx={10} className="gl-topo-card-box" />
                    <circle cx={entry.x + 16} cy={entry.y + 22} r={4.5} className="gl-topo-status-dot" data-tone={readyTone} />
                    <text x={entry.x + 28} y={entry.y + 26} className="gl-topo-card-title">
                      {truncateLabel(entry.name, 17)}
                    </text>
                    <text x={entry.x + 14} y={entry.y + 47} className="gl-topo-card-sub">
                      回执：{formatRevisionReceipt(entry.runtime?.revision, entry.runtime?.appliedRevision, !!entry.runtime?.runtimeReady)}
                    </text>
                    <text x={entry.x + 14} y={entry.y + 66} className="gl-topo-card-meta">
                      探测 {entry.observatory.intervalSec}s×{entry.observatory.sampling} · {entry.pooledRouteCount} 池
                      {entry.legacyThreeHopCount > 0 ? ` / ${entry.legacyThreeHopCount} 旧三跳` : ""} / {entry.twoHopRouteCount} 两跳
                    </text>
                  </g>
                );
              })}
            </g>

            {/* Column 2: Dashed RelayPool cards + Legacy Single-Relay cards */}
            <g className="gl-topo-layer-pools">
              {model.pools.map((poolNode) => {
                const selected = selection?.kind === "pool" && selection.id === poolNode.id;
                const connected =
                  !selection ||
                  selected ||
                  (selection.kind === "member" && selection.poolId === poolNode.id) ||
                  (selection.kind === "entry" &&
                    (model.entryPoolEdges.some((e) => e.entryId === selection.id && e.poolId === poolNode.id) ||
                      model.legacyEdges.some((e) => e.entryId === selection.id && e.pendingRelayPoolId === poolNode.id))) ||
                  (selection.kind === "landing" && model.allFullPaths.some((p) => p.poolId === poolNode.id && p.egressId === selection.id)) ||
                  (selection.kind === "path" && activePath?.poolId === poolNode.id) ||
                  (selection.kind === "legacy-route" && activeLegacyRoute?.pendingRelayPoolId === poolNode.id) ||
                  (selection.kind === "legacy-relay" && (activeLegacyRelay?.pendingPoolIds.includes(poolNode.id) ?? false));
                return (
                  <g
                    key={poolNode.id}
                    className="gl-topo-pool-group"
                    data-pool-id={poolNode.id}
                    data-selected={selected || undefined}
                    data-dimmed={!connected || undefined}
                  >
                    <g
                      role="button"
                      tabIndex={0}
                      aria-pressed={selected}
                      aria-label={`中转池 ${poolNode.name} · leastLoad 期望 ${poolNode.pool.strategy.expected} · ${poolNode.activeMemberCount}/${poolNode.members.length} 可用`}
                      onClick={() => toggleSelection({ kind: "pool", id: poolNode.id })}
                      onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "pool", id: poolNode.id }))}
                    >
                      <rect
                        x={poolNode.x}
                        y={poolNode.y}
                        width={poolNode.width}
                        height={poolNode.height}
                        rx={12}
                        strokeDasharray="6 4"
                        className="gl-topo-pool-box"
                      />
                      <text x={poolNode.x + 14} y={poolNode.y + 22} className="gl-topo-card-title">
                        {truncateLabel(poolNode.name, 20)}
                      </text>
                      <text x={poolNode.x + poolNode.width - 14} y={poolNode.y + 22} textAnchor="end" className="gl-topo-card-meta">
                        rev {poolNode.pool.revision}
                      </text>
                      <text x={poolNode.x + 14} y={poolNode.y + 40} className="gl-topo-card-meta">
                        leastLoad · 期望 {poolNode.pool.strategy.expected} · ≤{poolNode.pool.strategy.maxRttMs}ms · {poolNode.activeMemberCount}/
                        {poolNode.members.length} 就绪
                        {poolNode.revocationPending > 0 ? ` · ${poolNode.revocationPending} 撤销待回执` : ""}
                      </text>
                    </g>

                    {poolNode.members.length === 0 ? (
                      <text x={poolNode.x + 14} y={poolNode.y + 70} className="gl-topo-card-meta">
                        池内无成员（Fail-Closed 阻断）
                      </text>
                    ) : (
                      poolNode.members.map((slot) => {
                        const memberSelected =
                          selection?.kind === "member" && selection.poolId === slot.poolId && selection.nodeId === slot.nodeId;
                        const memberTone = slot.member.drained || slot.member.nodeSuspended
                          ? "warning"
                          : slot.member.runtimeReady
                            ? "good"
                            : "bad";
                        const stateTag = slot.member.drained
                          ? "已排空"
                          : slot.member.nodeSuspended
                            ? "节点停用"
                            : slot.member.runtimeReady
                              ? "就绪"
                              : "离线";
                        return (
                          <g
                            key={`${slot.poolId}:${slot.nodeId}`}
                            className="gl-topo-member-pill"
                            data-selected={memberSelected || undefined}
                            role="button"
                            tabIndex={0}
                            aria-pressed={memberSelected}
                            aria-label={`中转成员 #${slot.order} ${slot.name} · ${stateTag}`}
                            onClick={() => toggleSelection({ kind: "member", poolId: slot.poolId, nodeId: slot.nodeId })}
                            onKeyDown={(event) =>
                              handleSvgActivate(event, () =>
                                toggleSelection({ kind: "member", poolId: slot.poolId, nodeId: slot.nodeId }),
                              )
                            }
                          >
                            <rect
                              x={slot.x}
                              y={slot.y}
                              width={slot.width}
                              height={slot.height}
                              rx={7}
                              className="gl-topo-member-box"
                              data-tone={memberTone}
                            />
                            <circle cx={slot.x + 14} cy={slot.y + 17} r={4} className="gl-topo-status-dot" data-tone={memberTone} />
                            <text x={slot.x + 26} y={slot.y + 21} className="gl-topo-member-name">
                              #{slot.order} {truncateLabel(slot.name, 17)}
                            </text>
                            <text x={slot.x + slot.width - 10} y={slot.y + 21} textAnchor="end" className="gl-topo-member-state" data-tone={memberTone}>
                              {stateTag}
                            </text>
                          </g>
                        );
                      })
                    )}
                  </g>
                );
              })}

              {model.legacyRelays.map((legacy) => {
                const selected = selection?.kind === "legacy-relay" && selection.id === legacy.id;
                const connected =
                  !selection ||
                  selected ||
                  (selection.kind === "legacy-route" && activeLegacyRoute?.legacyRelayNodeId === legacy.id) ||
                  (selection.kind === "entry" && model.legacyEdges.some((e) => e.entryId === selection.id && e.legacyRelayNodeId === legacy.id)) ||
                  (selection.kind === "landing" && model.legacyEdges.some((e) => e.landingId === selection.id && e.legacyRelayNodeId === legacy.id)) ||
                  (selection.kind === "pool" && legacy.pendingPoolIds.includes(selection.id));
                const readyTone = legacy.suspended ? "warning" : legacy.runtime?.runtimeReady ? "good" : "muted";
                const pendingLabel =
                  legacy.pendingPoolIds.length > 0 ? `待切池：${legacy.pendingPoolIds.map(poolName).join("、")}` : "传统固定单中转";
                return (
                  <g
                    key={legacy.id}
                    className="gl-topo-card"
                    data-node-kind="legacy-relay"
                    data-selected={selected || undefined}
                    data-dimmed={!connected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`传统单中转 ${legacy.name} · ${pendingLabel}`}
                    onClick={() => toggleSelection({ kind: "legacy-relay", id: legacy.id })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "legacy-relay", id: legacy.id }))}
                  >
                    <rect
                      x={legacy.x}
                      y={legacy.y}
                      width={legacy.width}
                      height={legacy.height}
                      rx={10}
                      strokeDasharray="3 3"
                      className="gl-topo-legacy-box"
                    />
                    <circle cx={legacy.x + 16} cy={legacy.y + 22} r={4} className="gl-topo-status-dot" data-tone={readyTone} />
                    <text x={legacy.x + 28} y={legacy.y + 26} className="gl-topo-card-title">
                      旧三跳 · {truncateLabel(legacy.name, 16)}
                    </text>
                    <text x={legacy.x + 14} y={legacy.y + 48} className="gl-topo-card-meta">
                      {truncateLabel(pendingLabel, 34)} · {legacy.routeIds.length} 条线路
                    </text>
                  </g>
                );
              })}
            </g>

            {/* Column 3: Fixed Landing cards */}
            <g className="gl-topo-layer-landings">
              {model.landings.map((landingNode) => {
                const selected = selection?.kind === "landing" && selection.id === landingNode.id;
                const connected =
                  !selection ||
                  selected ||
                  (selection.kind === "entry" &&
                    (model.allFullPaths.some((p) => p.entryId === selection.id && p.egressId === landingNode.id) ||
                      model.twoHopEdges.some((e) => e.entryId === selection.id && e.landingId === landingNode.id) ||
                      model.legacyEdges.some((e) => e.entryId === selection.id && e.landingId === landingNode.id))) ||
                  (selection.kind === "pool" && model.allFullPaths.some((p) => p.poolId === selection.id && p.egressId === landingNode.id)) ||
                  (selection.kind === "member" &&
                    model.allFullPaths.some(
                      (p) => p.poolId === selection.poolId && p.relayNodeId === selection.nodeId && p.egressId === landingNode.id,
                    )) ||
                  (selection.kind === "legacy-relay" && model.legacyEdges.some((e) => e.legacyRelayNodeId === selection.id && e.landingId === landingNode.id)) ||
                  (selection.kind === "legacy-route" && activeLegacyRoute?.landingId === landingNode.id) ||
                  (selection.kind === "path" && activePath?.egressId === landingNode.id) ||
                  (selection.kind === "two-hop" && activeTwoHop?.landingId === landingNode.id);
                const readyTone = landingNode.suspended ? "warning" : landingNode.runtime?.runtimeReady ? "good" : "muted";
                const occupiedCount = landingNode.runtime?.occupiedPort24000?.length ?? 0;
                return (
                  <g
                    key={landingNode.id}
                    className="gl-topo-card"
                    data-node-kind="landing"
                    data-selected={selected || undefined}
                    data-dimmed={!connected || undefined}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selected}
                    aria-label={`固定出口 ${landingNode.name} · ${formatRevisionReceipt(landingNode.runtime?.revision, landingNode.runtime?.appliedRevision, !!landingNode.runtime?.runtimeReady)}`}
                    onClick={() => toggleSelection({ kind: "landing", id: landingNode.id })}
                    onKeyDown={(event) => handleSvgActivate(event, () => toggleSelection({ kind: "landing", id: landingNode.id }))}
                  >
                    <rect
                      x={landingNode.x}
                      y={landingNode.y}
                      width={landingNode.width}
                      height={landingNode.height}
                      rx={10}
                      className="gl-topo-card-box"
                    />
                    <circle cx={landingNode.x + 16} cy={landingNode.y + 22} r={4.5} className="gl-topo-status-dot" data-tone={readyTone} />
                    <text x={landingNode.x + 28} y={landingNode.y + 26} className="gl-topo-card-title">
                      {truncateLabel(landingNode.name, 17)}
                    </text>
                    <text x={landingNode.x + 14} y={landingNode.y + 47} className="gl-topo-card-sub">
                      回执：{formatRevisionReceipt(landingNode.runtime?.revision, landingNode.runtime?.appliedRevision, !!landingNode.runtime?.runtimeReady)}
                    </text>
                    <text x={landingNode.x + 14} y={landingNode.y + 66} className="gl-topo-card-meta">
                      {landingNode.incomingPooled} 池入
                      {landingNode.incomingLegacyThreeHop > 0 ? ` / ${landingNode.incomingLegacyThreeHop} 旧三跳` : ""} / {landingNode.incomingTwoHop} 两跳
                      {occupiedCount > 0 ? ` · ${occupiedCount} 个 24000 待切窗` : landingNode.runtime?.relayPoolCapable ? " · EIH 24000" : ""}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>
      )}

      {/* Interactive detail & full-path telemetry breakdown */}
      <section className="gl-topology-detail" aria-label="拓扑状态与完整路径详情">
        <div className="gl-topology-summary-strip">
          <span>已准入三跳完整路径：{stats.admitted}</span>
          <span>健康：{stats.healthy}</span>
          <span>探测失败：{stats.unhealthy}</span>
          <span>样本过期：{stats.stale}</span>
          <span>尚无样本：{stats.noSample}</span>
          {model.legacyEdges.length > 0 ? <span>待切 / 传统三跳：{model.legacyEdges.length}</span> : null}
          {stats.blockedEntries > 0 ? <strong className="gl-topo-alert-text">池空阻断：{stats.blockedEntries}</strong> : null}
        </div>

        {activeEntry ? (
          <div className="gl-topology-focus-card">
            <div className="gl-topology-focus-head">
              <div>
                <h3>入口：{activeEntry.name}</h3>
                <p className="gl-context-copy">
                  期望修订 R{activeEntry.runtime?.revision ?? "—"} · 应用回执{" "}
                  {formatRevisionReceipt(activeEntry.runtime?.revision, activeEntry.runtime?.appliedRevision, !!activeEntry.runtime?.runtimeReady)}
                  {" · "}
                  探测目标 {activeEntry.observatory.destination}（{activeEntry.observatory.intervalSec}s / 采样 {activeEntry.observatory.sampling} / 超时{" "}
                  {activeEntry.observatory.timeoutSec}s）
                </p>
              </div>
              {activeEntry.runtime && onEditEntryObservatory ? (
                <Button type="button" variant="outline" onClick={() => onEditEntryObservatory(activeEntry.runtime!)}>
                  编辑探测与源地址
                </Button>
              ) : null}
            </div>
          </div>
        ) : null}

        {activePool ? (
          <div className="gl-topology-focus-card">
            <div className="gl-topology-focus-head">
              <div>
                <h3>中转池：{activePool.name}</h3>
                <p className="gl-context-copy">
                  期望配置 rev {activePool.pool.revision} · leastLoad(expected={activePool.pool.strategy.expected}, maxRtt={activePool.pool.strategy.maxRttMs}ms,
                  tolerance={activePool.pool.strategy.tolerance ?? 0}) · 撤销回执：
                  {activePool.pool.revocation?.complete !== false
                    ? "已完成"
                    : `待回执入口 ${activePool.pool.revocation.pendingEntries.length} / 落地 ${activePool.pool.revocation.pendingLandings.length}`}
                </p>
              </div>
              {onEditPool ? (
                <Button type="button" variant="outline" onClick={() => onEditPool(activePool.pool)}>
                  编辑中转池
                </Button>
              ) : null}
            </div>
          </div>
        ) : null}

        {activeMember ? (
          <div className="gl-topology-focus-card">
            <h3>
              中转成员 #{activeMember.order}：{activeMember.name}
            </h3>
            <p className="gl-context-copy">
              期望配置：{activeMember.member.drained ? `已排空${activeMember.member.drainReason ? `（${activeMember.member.drainReason}）` : ""}` : "参与池选路"}
              {" · "}
              节点回执：{formatRevisionReceipt(activeMember.runtime?.revision, activeMember.runtime?.appliedRevision, activeMember.member.runtimeReady)}
              {activeMember.member.nodeSuspended ? " · 节点级临时停用生效中" : ""}
            </p>
          </div>
        ) : null}

        {activeLegacyRelay ? (
          <div className="gl-topology-focus-card">
            <h3>传统固定中转：{activeLegacyRelay.name}</h3>
            <p className="gl-context-copy">
              当前仍承载 {activeLegacyRelay.routeIds.length} 条传统单中转三跳线路（不属于两跳直连）
              {activeLegacyRelay.pendingPoolIds.length > 0 ? ` · 待切换至中转池：${activeLegacyRelay.pendingPoolIds.map(poolName).join("、")}` : ""}
              {" · "}
              节点回执：{formatRevisionReceipt(activeLegacyRelay.runtime?.revision, activeLegacyRelay.runtime?.appliedRevision, !!activeLegacyRelay.runtime?.runtimeReady)}
            </p>
          </div>
        ) : null}

        {activeLegacyRoute ? (
          <div className="gl-topology-focus-card">
            <h3>
              传统三跳：{nodeName(activeLegacyRoute.entryId)} → {nodeName(activeLegacyRoute.relayNodeId)} → {nodeName(activeLegacyRoute.landingId)}
            </h3>
            <p className="gl-context-copy">
              期望配置：{activeLegacyRoute.desiredEnabled ? "启用" : "停用"}
              {activeLegacyRoute.pendingRelayPoolId ? ` · 保留旧三跳运行，待显式切换至中转池「${poolName(activeLegacyRoute.pendingRelayPoolId)}」` : ""}
              {" · "}
              节点回执：入口{activeLegacyRoute.entryReady ? "已应用" : "待回执"} / 中转{activeLegacyRoute.relayReady ? "已应用" : "待回执"} / 落地
              {activeLegacyRoute.landingReady ? "已应用" : "待回执"}
            </p>
          </div>
        ) : null}

        {activeLanding ? (
          <div className="gl-topology-focus-card">
            <h3>固定出口：{activeLanding.name}</h3>
            <p className="gl-context-copy">
              节点回执：{formatRevisionReceipt(activeLanding.runtime?.revision, activeLanding.runtime?.appliedRevision, !!activeLanding.runtime?.runtimeReady)}
              {activeLanding.runtime?.egressIp ? ` · 固定出口 IP ${activeLanding.runtime.egressIp}` : ""}
              {(activeLanding.runtime?.occupiedPort24000?.length ?? 0) > 0
                ? ` · 端口 24000 单用户占用地址：${activeLanding.runtime!.occupiedPort24000!.join(", ")}`
                : ""}
            </p>
          </div>
        ) : null}

        {activeTwoHop ? (
          <div className="gl-topology-focus-card">
            <h3>
              两跳直连：{nodeName(activeTwoHop.entryId)} → {nodeName(activeTwoHop.landingId)}
            </h3>
            <p className="gl-context-copy">
              期望配置：{activeTwoHop.desiredEnabled ? "启用" : "停用"}
              {activeTwoHop.route.udp ? " · UDP(XUDP)" : " · TCP-only"}
              {" · "}
              节点回执：入口{activeTwoHop.entryReady ? "已应用" : "待回执"} / 落地{activeTwoHop.landingReady ? "已应用" : "待回执"}
              {" · "}
              TCP 采样：{twoHopTelemetryLabel(activeTwoHop)}
              {activeTwoHop.checkedAt ? `（${formatSampleAge(activeTwoHop.checkedAt, now)}）` : ""}
            </p>
          </div>
        ) : null}

        {selectedPaths.length > 0 ? (
          <div className="gl-table-scroll">
            <table className="gl-data-table gl-topo-path-table">
              <thead>
                <tr>
                  <th>完整路径（入口 → 中转池 / 成员 → 固定出口）</th>
                  <th>期望配置</th>
                  <th>节点回执（准入）</th>
                  <th>探活采样（健康 / RTT / 样本）</th>
                </tr>
              </thead>
              <tbody>
                {selectedPaths.map((path) => {
                  const tone = pathStrokeTone(path);
                  const sample = path.telemetry;
                  const pathSelected = selection?.kind === "path" && selection.id === path.id;
                  const rttDetail =
                    sample.state === "healthy" || sample.state === "stale"
                      ? `${sample.delayMs ?? 0}ms${sample.averageMs ? `（均 ${sample.averageMs}ms · ${sample.minMs ?? 0}-${sample.maxMs ?? 0}ms）` : ""}`
                      : sample.state === "unhealthy"
                        ? sample.lastErrorReason || "探活失败"
                        : "尚无观测样本";
                  return (
                    <tr
                      key={path.id}
                      data-selected={pathSelected}
                      onClick={() => toggleSelection({ kind: "path", id: path.id })}
                    >
                      <td>
                        <button
                          type="button"
                          className="gl-route-name"
                          aria-pressed={pathSelected}
                          onClick={(event) => {
                            event.stopPropagation();
                            toggleSelection({ kind: "path", id: path.id });
                          }}
                        >
                          {nodeName(path.entryId)} → #{path.memberOrder} {nodeName(path.relayNodeId)} → {nodeName(path.egressId)}
                        </button>
                        <small className="gl-route-meta">
                          池 {poolName(path.poolId)}
                          {path.route.name ? ` · ${path.route.name}` : ""}
                          {path.route.egressIp ? ` · 出口 ${path.route.egressIp}` : ""}
                        </small>
                      </td>
                      <td>
                        <span>{path.desiredRouteEnabled ? "线路启用" : "线路停用"}</span>
                        <small className="gl-route-meta">
                          {path.memberDrained ? `成员已排空${path.drainReason ? `：${path.drainReason}` : ""}` : path.nodeSuspended ? "节点级停用" : "候选参与"}
                        </small>
                      </td>
                      <td>
                        <span className="gl-status" data-tone={path.admitted ? "good" : "warning"}>
                          {path.admitted ? "已准入" : "未准入"}
                        </span>
                        <small className="gl-route-meta">
                          入 {path.entryRuntimeReady ? `R${path.entryAppliedRev || path.entryDesiredRev}` : "待回执"} · 转{" "}
                          {path.relayRuntimeReady ? `R${path.relayAppliedRev || path.relayDesiredRev}` : "离线/待回执"} · 落{" "}
                          {path.landingRuntimeReady ? `R${path.landingAppliedRev || path.landingDesiredRev}` : "待回执"}
                        </small>
                      </td>
                      <td>
                        <span className="gl-status" data-tone={tone === "bad" ? "warning" : tone}>
                          {pathTelemetryLabel(path)}
                        </span>
                        <small className="gl-route-meta">
                          {rttDetail}
                          {sample.allSamples > 0 ? ` · 失败 ${sample.failedSamples}/${sample.allSamples}` : ""}
                          {sample.sampledAt ? ` · ${formatSampleAge(sample.sampledAt, now)}` : ""}
                        </small>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : selectedTwoHop.length === 0 && selectedLegacy.length === 0 ? (
          <p className="gl-context-copy">
            点击上方拓扑中的任意入口、中转池、成员、固定出口或连线，可高亮关联路径并查看期望配置、节点回执与低频采样明细。
          </p>
        ) : null}
        <p className="gl-context-copy">
          说明：burstObservatory 采样仅反映入口经该完整路径的展示与选路观测结果，不等于控制面配置回执，也不会触发节点配置重载或进程重启。
        </p>
      </section>
    </section>
  );
}
