import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Plus, RefreshCw, Settings2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { RouteLatency } from "./RouteLatency";
import { useControlRequest } from "./ControlAccess";
import type {
  Inventory,
  RelayPoolMemberView,
  RelayPoolView,
  SocketCutoverPlan,
} from "./control-types";
import {
  MAX_DRAIN_REASON_RUNES,
  buildRelayPoolChangePayload,
  canStartSocketCutover,
  cutoverConsumerKindLabel,
  cutoverPhaseLabel,
  effectiveEntryObservatory,
  formatRevisionReceipt,
  isCutoverConsumerMigratable,
  isValidDrainReason,
  isZeroTimestamp,
  normalizeRelayPoolMember,
  type InspectedCutoverState,
} from "./relay-pool-model";
import { EntryObservatoryEditor, RelayPoolEditor } from "./RelayPoolForms";
import { RelayTopology } from "./RelayTopology";

type SubTab = "pools" | "observatory" | "cutover";
type PoolEditorTarget = { mode: "create" } | { mode: "edit"; id: string } | null;

export function RelayPoolWorkspace({
  inventory,
  names,
  disabled,
  standalone = false,
  save,
  latency,
}: {
  inventory: Inventory;
  names: Map<string, string>;
  disabled: boolean;
  standalone?: boolean;
  save: (operation: string, body: unknown) => Promise<boolean>;
  latency: { values: Map<string, RouteLatency>; now: number; error: string };
}) {
  const manage = useControlRequest();
  const [subTab, setSubTab] = useState<SubTab>("pools");
  const [poolEditorTarget, setPoolEditorTarget] = useState<PoolEditorTarget>(null);
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [drainTarget, setDrainTarget] = useState<{ poolId: string; nodeId: string } | null>(null);
  const [drainReason, setDrainReason] = useState("");
  const [drainResumeAt, setDrainResumeAt] = useState("");
  const [drainError, setDrainError] = useState("");
  const [confirmRemoveMember, setConfirmRemoveMember] = useState<string>("");
  const [confirmDeletePool, setConfirmDeletePool] = useState<string>("");
  const [cutoverPlans, setCutoverPlans] = useState<Record<string, InspectedCutoverState>>({});
  const [inspectError, setInspectError] = useState("");
  const inspectSeq = useRef<Record<string, number>>({});
  const inspectAbort = useRef<Record<string, AbortController>>({});

  useEffect(() => {
    return () => {
      for (const controller of Object.values(inspectAbort.current)) {
        controller.abort();
      }
      inspectAbort.current = {};
    };
  }, []);

  const pools = inventory.relayPools ?? [];
  const entries = useMemo(() => inventory.runtimes.filter((rt) => rt.role === "entry"), [inventory.runtimes]);
  const editingPool =
    poolEditorTarget?.mode === "edit" ? pools.find((p) => p.id === poolEditorTarget.id) ?? null : null;
  const showPoolSheet = poolEditorTarget?.mode === "create" || (poolEditorTarget?.mode === "edit" && !!editingPool);
  const editingEntry = editingEntryId ? entries.find((e) => e.id === editingEntryId) ?? null : null;
  const occupiedLandings = useMemo(
    () => inventory.runtimes.filter((rt) => rt.role === "landing" && (rt.occupiedPort24000?.length ?? 0) > 0),
    [inventory.runtimes],
  );
  const cutovers = inventory.socketCutovers ?? [];
  const legacyCutoverRoutes = useMemo(
    () => inventory.routes.filter((r) => r.pendingLegacyCutover || r.retiringLegacyTransport),
    [inventory.routes],
  );
  const runtimesById = useMemo(() => new Map(inventory.runtimes.map((rt) => [rt.id, rt])), [inventory.runtimes]);
  const nodeName = (id: string) => names.get(id) ?? id;

  const submitPoolMutation = async (pool: RelayPoolView, nextMembers: RelayPoolMemberView[]) => {
    await save(
      "relay-pools",
      buildRelayPoolChangePayload({
        id: pool.id,
        name: pool.name,
        revision: pool.revision,
        expectedRevision: pool.revision,
        strategy: pool.strategy,
        members: nextMembers,
      }),
    );
  };

  const reorderMember = async (pool: RelayPoolView, index: number, delta: -1 | 1) => {
    const nextIndex = index + delta;
    if (nextIndex < 0 || nextIndex >= pool.members.length) return;
    const copy = [...pool.members];
    const [moved] = copy.splice(index, 1);
    copy.splice(nextIndex, 0, moved);
    await submitPoolMutation(pool, copy);
  };

  const submitDrain = async (pool: RelayPoolView, nodeId: string) => {
    setDrainError("");
    const date = drainResumeAt ? new Date(drainResumeAt) : undefined;
    if (date && (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now())) {
      setDrainError("请选择未来的自动恢复时间，或留空改为手动恢复。");
      return;
    }
    const reason = drainReason.trim();
    if (reason && !isValidDrainReason(reason)) {
      setDrainError(`排空原因最多 ${MAX_DRAIN_REASON_RUNES} 个字符，且不能包含换行或控制字符。`);
      return;
    }
    const nextMembers = pool.members.map((member) =>
      member.nodeId === nodeId
        ? {
            ...normalizeRelayPoolMember(member),
            drained: true,
            drainReason: reason || undefined,
            drainResumeAt: date?.toISOString(),
          }
        : normalizeRelayPoolMember(member),
    );
    const ok = await save(
      "relay-pools",
      buildRelayPoolChangePayload({
        id: pool.id,
        name: pool.name,
        revision: pool.revision,
        expectedRevision: pool.revision,
        strategy: pool.strategy,
        members: nextMembers,
      }),
    );
    if (ok) {
      setDrainTarget(null);
      setDrainReason("");
      setDrainResumeAt("");
    }
  };

  const resumeMember = async (pool: RelayPoolView, nodeId: string) => {
    const nextMembers = pool.members.map((member) =>
      member.nodeId === nodeId
        ? {
            ...normalizeRelayPoolMember(member),
            drained: false,
            drainReason: undefined,
            drainResumeAt: undefined,
          }
        : normalizeRelayPoolMember(member),
    );
    await save(
      "relay-pools",
      buildRelayPoolChangePayload({
        id: pool.id,
        name: pool.name,
        revision: pool.revision,
        expectedRevision: pool.revision,
        strategy: pool.strategy,
        members: nextMembers,
      }),
    );
  };

  const removeMemberImmediately = async (pool: RelayPoolView, nodeId: string) => {
    const nextMembers = pool.members.filter((member) => member.nodeId !== nodeId).map(normalizeRelayPoolMember);
    const ok = await save(
      "relay-pools",
      buildRelayPoolChangePayload({
        id: pool.id,
        name: pool.name,
        revision: pool.revision,
        expectedRevision: pool.revision,
        strategy: pool.strategy,
        members: nextMembers,
      }),
    );
    if (ok) setConfirmRemoveMember("");
  };

  const deletePool = async (pool: RelayPoolView) => {
    const ok = await save(
      "relay-pools",
      buildRelayPoolChangePayload({
        id: pool.id,
        name: pool.name,
        revision: pool.revision,
        expectedRevision: pool.revision,
        strategy: pool.strategy,
        members: [],
        delete: true,
      }),
    );
    if (ok) setConfirmDeletePool("");
  };

  const inspectCutover = async (targetNodeId: string, address: string, targetRevision: string) => {
    const key = `${targetNodeId}/${address}`;
    inspectAbort.current[key]?.abort();
    const controller = new AbortController();
    inspectAbort.current[key] = controller;
    const seq = (inspectSeq.current[key] ?? 0) + 1;
    inspectSeq.current[key] = seq;
    setInspectError("");
    // Immediately invalidate prior inspect while re-inspect is in flight so stale previews cannot start.
    setCutoverPlans((prev) => ({
      ...prev,
      [key]: { seq, pending: true },
    }));
    try {
      const plan = await manage<SocketCutoverPlan>(
        "socket-cutover",
        {
          action: "inspect",
          targetNodeId,
          address,
        },
        controller.signal,
      );
      if (controller.signal.aborted || inspectSeq.current[key] !== seq) return;
      setCutoverPlans((prev) => ({
        ...prev,
        [key]: { seq, pending: false, plan, inspectedRevision: targetRevision },
      }));
    } catch (failure) {
      if (controller.signal.aborted || inspectSeq.current[key] !== seq) return;
      const message = failure instanceof Error ? failure.message : "端口 24000 占用检查失败。";
      setInspectError(message);
      setCutoverPlans((prev) => ({
        ...prev,
        [key]: { seq, pending: false, failed: message },
      }));
    } finally {
      if (inspectAbort.current[key] === controller) {
        delete inspectAbort.current[key];
      }
    }
  };

  return (
    <div className="gl-pools-workspace">
      <RelayTopology
        inventory={inventory}
        names={names}
        latencies={latency.values}
        now={latency.now}
        latencyFailed={!!latency.error}
        onEditPool={(pool) => setPoolEditorTarget({ mode: "edit", id: pool.id })}
        onEditEntryObservatory={(entry) => setEditingEntryId(entry.id)}
      />

      <div className="gl-toolbar gl-pools-toolbar">
        <div className="gl-segment" role="group" aria-label="中转池管理视图">
          <button type="button" aria-pressed={subTab === "pools"} onClick={() => setSubTab("pools")}>
            中转池管理（{pools.length}）
          </button>
          <button type="button" aria-pressed={subTab === "observatory"} onClick={() => setSubTab("observatory")}>
            入口探测与源地址（{entries.length}）
          </button>
          <button type="button" aria-pressed={subTab === "cutover"} onClick={() => setSubTab("cutover")}>
            端口 24000 切窗与迁移（{cutovers.length + legacyCutoverRoutes.length + occupiedLandings.length}）
          </button>
        </div>
        {subTab === "pools" ? (
          <Button type="button" disabled={disabled} onClick={() => setPoolEditorTarget({ mode: "create" })}>
            <Plus />
            新增中转池
          </Button>
        ) : null}
      </div>

      {subTab === "pools" ? (
        <section className="gl-pools-section" aria-label="中转池列表">
          {pools.length === 0 ? (
            <div className="gl-empty">
              <h3>尚未创建中转池</h3>
              <p>创建有序中转池后，即可在「线路组合」中为固定落地绑定三跳池化线路。</p>
            </div>
          ) : (
            <div className="gl-pools-grid">
              {pools.map((pool) => {
                const pendingEntries = pool.revocation?.pendingEntries ?? [];
                const pendingLandings = pool.revocation?.pendingLandings ?? [];
                const revocationComplete = pool.revocation ? pool.revocation.complete : true;
                return (
                  <article key={pool.id} className="gl-pool-card" data-pool-id={pool.id}>
                    <header className="gl-pool-card-header">
                      <div>
                        <h3>
                          {pool.name} <small>（{pool.id} · rev {pool.revision}）</small>
                        </h3>
                        <p className="gl-context-copy">
                          策略 leastLoad：期望并发 {pool.strategy.expected} · 最大 RTT {pool.strategy.maxRttMs}ms · 容差{" "}
                          {pool.strategy.tolerance ?? 0} · 关联线路 {pool.routeIds.length} 条
                        </p>
                      </div>
                      <div className="gl-pool-card-actions">
                        <Button type="button" variant="outline" disabled={disabled} onClick={() => setPoolEditorTarget({ mode: "edit", id: pool.id })}>
                          <Settings2 />
                          编辑池
                        </Button>
                        {confirmDeletePool === pool.id ? (
                          <div className="gl-inline-confirm" role="group" aria-label={`确认删除中转池 ${pool.name}`}>
                            <Button type="button" variant="outline" disabled={disabled} onClick={() => setConfirmDeletePool("")}>
                              取消
                            </Button>
                            <Button
                              type="button"
                              variant="destructive"
                              disabled={disabled || pool.routeIds.length > 0}
                              onClick={() => void deletePool(pool)}
                            >
                              确认删除
                            </Button>
                          </div>
                        ) : (
                          <Button
                            type="button"
                            variant="ghost"
                            disabled={disabled || pool.routeIds.length > 0}
                            title={pool.routeIds.length > 0 ? "仍有线路引用该中转池，请先删除对应线路。" : "删除中转池"}
                            onClick={() => setConfirmDeletePool(pool.id)}
                          >
                            删除池
                          </Button>
                        )}
                      </div>
                    </header>

                    <div className="gl-pool-revocation-bar" data-complete={revocationComplete ? "true" : "false"}>
                      <span className="gl-status" data-tone={revocationComplete ? "good" : "warning"}>
                        {revocationComplete ? "节点应用回执已同步" : "撤销 / 变更回执待同步"}
                      </span>
                      {!revocationComplete ? (
                        <small>
                          {pendingEntries.length > 0 ? `待回执入口：${pendingEntries.map(nodeName).join("、")}` : ""}
                          {pendingEntries.length > 0 && pendingLandings.length > 0 ? "；" : ""}
                          {pendingLandings.length > 0 ? `待回执落地：${pendingLandings.map(nodeName).join("、")}` : ""}
                          （离线已摘除中转不阻塞撤销完成）
                        </small>
                      ) : null}
                    </div>

                    {pool.members.length === 0 ? (
                      <p className="gl-context-copy">
                        池内暂无中转成员；绑定此池的线路将按 Fail-Closed 处于阻断状态，直到加入并准入有效成员。
                      </p>
                    ) : (
                      <ol className="gl-pool-member-list">
                        {pool.members.map((member, index) => {
                          const rt = runtimesById.get(member.nodeId);
                          const removeKey = `${pool.id}/${member.nodeId}`;
                          const isDrainingThis = drainTarget?.poolId === pool.id && drainTarget.nodeId === member.nodeId;
                          return (
                            <li key={member.nodeId} className="gl-pool-member-row">
                              <div className="gl-pool-member-main">
                                <span className="gl-pool-order-badge">#{index + 1}</span>
                                <div className="gl-pool-member-info">
                                  <strong>{nodeName(member.nodeId)}</strong>
                                  <small>
                                    入站 {[member.ingressIpv4, member.ingressIpv6].filter(Boolean).join(" / ") || "—"} · 出站{" "}
                                    {[member.egressIpv4, member.egressIpv6].filter(Boolean).join(" / ") || "—"}
                                  </small>
                                  <div className="gl-pool-member-badges">
                                    <span className="gl-status" data-tone={member.drained ? "warning" : "good"}>
                                      期望：{member.drained ? "成员已排空" : "参与选路"}
                                    </span>
                                    <span className="gl-status" data-tone={member.runtimeReady ? "good" : "muted"}>
                                      回执：{formatRevisionReceipt(rt?.revision, rt?.appliedRevision, member.runtimeReady)}
                                    </span>
                                    {member.nodeSuspended ? (
                                      <span className="gl-status" data-tone="warning">
                                        节点级临时停用
                                      </span>
                                    ) : null}
                                  </div>
                                  {member.drained ? (
                                    <small>
                                      排空说明：{member.drainReason || "未填写原因"}
                                      {member.drainResumeAt && !isZeroTimestamp(member.drainResumeAt)
                                        ? ` · 计划恢复 ${new Date(member.drainResumeAt).toLocaleString()}`
                                        : " · 手动恢复"}
                                    </small>
                                  ) : null}
                                </div>
                                <div className="gl-pool-member-ops">
                                  <Button
                                    type="button"
                                    variant="outline"
                                    disabled={disabled || index === 0}
                                    aria-label={`上移 ${pool.name} 成员 ${nodeName(member.nodeId)}`}
                                    onClick={() => void reorderMember(pool, index, -1)}
                                  >
                                    <ArrowUp />
                                  </Button>
                                  <Button
                                    type="button"
                                    variant="outline"
                                    disabled={disabled || index === pool.members.length - 1}
                                    aria-label={`下移 ${pool.name} 成员 ${nodeName(member.nodeId)}`}
                                    onClick={() => void reorderMember(pool, index, 1)}
                                  >
                                    <ArrowDown />
                                  </Button>
                                  {member.drained ? (
                                    <Button
                                      type="button"
                                      variant="outline"
                                      disabled={disabled}
                                      onClick={() => void resumeMember(pool, member.nodeId)}
                                    >
                                      恢复候选
                                    </Button>
                                  ) : (
                                    <Button
                                      type="button"
                                      variant="outline"
                                      disabled={disabled}
                                      onClick={() => {
                                        setDrainTarget({ poolId: pool.id, nodeId: member.nodeId });
                                        setDrainReason(member.drainReason ?? "");
                                        setDrainResumeAt("");
                                        setDrainError("");
                                      }}
                                    >
                                      排空
                                    </Button>
                                  )}
                                  {confirmRemoveMember === removeKey ? (
                                    <div className="gl-inline-confirm" role="group" aria-label={`确认摘除成员 ${nodeName(member.nodeId)}`}>
                                      <Button type="button" variant="outline" disabled={disabled} onClick={() => setConfirmRemoveMember("")}>
                                        取消
                                      </Button>
                                      <Button
                                        type="button"
                                        variant="destructive"
                                        disabled={disabled}
                                        onClick={() => void removeMemberImmediately(pool, member.nodeId)}
                                      >
                                        确认摘除
                                      </Button>
                                    </div>
                                  ) : (
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      disabled={disabled}
                                      onClick={() => setConfirmRemoveMember(removeKey)}
                                    >
                                      {member.runtimeReady ? "摘除" : "离线摘除"}
                                    </Button>
                                  )}
                                </div>
                              </div>

                              {confirmRemoveMember === removeKey ? (
                                <p className="gl-context-copy">
                                  {member.runtimeReady
                                    ? "摘除后将从入口候选和下游落地 EIH 24000 授权中撤销该成员的凭证，无需停用整池。"
                                    : "该中转当前离线；离线摘除会立即向在线入口和下游落地提交撤销配置，撤销进度以入口与落地回执为准。"}
                                </p>
                              ) : null}

                              {isDrainingThis ? (
                                <form
                                  className="gl-drain-inline-form"
                                  onSubmit={(event) => {
                                    event.preventDefault();
                                    void submitDrain(pool, member.nodeId);
                                  }}
                                >
                                  <p className="gl-context-copy">
                                    成员排空仅将此节点移出「{pool.name}」候选，不影响该主机作为固定落地的其他线路。
                                  </p>
                                  <div className="gl-drain-inline-fields">
                                    <label>
                                      排空原因（可选）
                                      <Input
                                        disabled={disabled}
                                        placeholder="例如：路由维护 / 晚高峰绕行"
                                        value={drainReason}
                                        onChange={(event) => setDrainReason(event.target.value)}
                                      />
                                    </label>
                                    <label>
                                      自动恢复时间（可选，本机时区；留空手动恢复）
                                      <Input
                                        type="datetime-local"
                                        disabled={disabled}
                                        value={drainResumeAt}
                                        onChange={(event) => setDrainResumeAt(event.target.value)}
                                      />
                                    </label>
                                  </div>
                                  {drainError ? (
                                    <p role="alert" className="text-destructive">
                                      {drainError}
                                    </p>
                                  ) : null}
                                  <div className="gl-drain-inline-actions">
                                    <Button type="button" variant="outline" disabled={disabled} onClick={() => setDrainTarget(null)}>
                                      <X />
                                      取消
                                    </Button>
                                    <Button type="submit" disabled={disabled}>
                                      确认排空
                                    </Button>
                                  </div>
                                </form>
                              ) : null}
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </article>
                );
              })}
            </div>
          )}
        </section>
      ) : null}

      {subTab === "observatory" ? (
        <section className="gl-pools-section" aria-label="入口探测与源地址配置">
          <div className="gl-table-scroll">
            <table className="gl-data-table">
              <thead>
                <tr>
                  <th>入口节点</th>
                  <th>应用回执与能力</th>
                  <th>公网中转源地址</th>
                  <th>burstObservatory 探测配置</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => {
                  const cfg = inventory.entryRelayConfigs?.[entry.id];
                  const obs = effectiveEntryObservatory(entry.id, inventory.entryRelayConfigs);
                  return (
                    <tr key={entry.id}>
                      <td>
                        <strong>{nodeName(entry.id)}</strong>
                        <small className="gl-route-meta">{entry.id}</small>
                      </td>
                      <td>
                        <span className="gl-status" data-tone={entry.runtimeReady ? "good" : "muted"}>
                          {formatRevisionReceipt(entry.revision, entry.appliedRevision, entry.runtimeReady)}
                        </span>
                        <small className="gl-route-meta">{entry.relayPoolCapable ? "支持池化三跳" : "未上报池化能力"}</small>
                      </td>
                      <td>
                        <div>IPv4: {cfg?.sourceIpv4 || entry.publicIpv4 || "—"}</div>
                        <small className="gl-route-meta">IPv6: {cfg?.sourceIpv6 || entry.publicIpv6 || "—"}</small>
                      </td>
                      <td>
                        <div>{obs.config.destination}</div>
                        <small className="gl-route-meta">
                          间隔 {obs.config.intervalSec}s · 采样 {obs.config.sampling} 次 · 超时 {obs.config.timeoutSec}s
                          {obs.custom ? "（已自定义）" : "（默认）"}
                        </small>
                      </td>
                      <td>
                        <Button type="button" variant="outline" disabled={disabled} onClick={() => setEditingEntryId(entry.id)}>
                          编辑配置
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {subTab === "cutover" ? (
        <section className="gl-pools-section" aria-label="端口 24000 切窗与旧三跳迁移">
          {inspectError ? (
            <p role="alert" className="gl-inline-error">
              {inspectError}
            </p>
          ) : null}

          <div className="gl-cutover-block">
            <h3>待切换旧三跳线路（{legacyCutoverRoutes.length}）</h3>
            {legacyCutoverRoutes.length === 0 ? (
              <p className="gl-context-copy">当前没有处于待切换或旧三跳退场阶段的迁移线路。</p>
            ) : (
              <div className="gl-table-scroll">
                <table className="gl-data-table">
                  <thead>
                    <tr>
                      <th>线路</th>
                      <th>旧中转 → 目标中转池</th>
                      <th>当前阶段</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {legacyCutoverRoutes.map((route) => {
                      const poolId = route.pendingRelayPoolId || route.relayPoolId || "";
                      const poolName = pools.find((p) => p.id === poolId)?.name ?? poolId;
                      return (
                        <tr key={route.id}>
                          <td>
                            <strong>
                              {nodeName(route.entryId)} → {nodeName(route.egressId)}
                            </strong>
                            <small className="gl-route-meta">{route.id}</small>
                          </td>
                          <td>
                            {route.relayId ? nodeName(route.relayId) : "—"} → {poolName || "—"}
                          </td>
                          <td>
                            <span className="gl-status" data-tone="warning">
                              {route.pendingLegacyCutover ? "保留旧三跳（等待切换）" : "旧三跳退场中（等待入口回执）"}
                            </span>
                          </td>
                          <td>
                            {route.pendingLegacyCutover ? (
                              <Button
                                type="button"
                                variant="outline"
                                disabled={disabled}
                                onClick={() => void save("socket-cutover", { action: "cutover-legacy", grantId: route.id })}
                              >
                                切换至中转池
                              </Button>
                            ) : (
                              <span className="gl-secondary">等待入口回执自动清理</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="gl-cutover-block">
            <h3>进行中的端口 24000 切窗（{cutovers.length}）</h3>
            {cutovers.length === 0 ? (
              <p className="gl-context-copy">当前没有活跃的端口 24000 受控切窗窗口。</p>
            ) : (
              <div className="gl-pools-grid">
                {cutovers.map((cutover) => (
                  <article key={cutover.id} className="gl-pool-card">
                    <header className="gl-pool-card-header">
                      <div>
                        <h3>
                          {nodeName(cutover.targetNodeId)} · {cutover.address}:{cutover.port}
                        </h3>
                        <p className="gl-context-copy">
                          阶段：{cutoverPhaseLabel(cutover.phase)} · 目标监听修订 R{cutover.listenerRevision}（
                          {cutover.listenerApplied ? "监听回执已确认" : "等待监听回执"}）
                        </p>
                        <p className="gl-context-copy">
                          关联入口：{cutover.consumerEntryIds.map(nodeName).join("、") || "无"}
                          {cutover.pendingEntries.length > 0 ? ` · 待回执入口：${cutover.pendingEntries.map(nodeName).join("、")}` : ""}
                        </p>
                      </div>
                      <div className="gl-pool-card-actions">
                        <Button
                          type="button"
                          variant="outline"
                          disabled={disabled}
                          onClick={() => void save("socket-cutover", { action: "advance", cutoverId: cutover.id })}
                        >
                          <RefreshCw />
                          推进切窗
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          disabled={disabled}
                          onClick={() => void save("socket-cutover", { action: "rollback", cutoverId: cutover.id })}
                        >
                          回滚切窗
                        </Button>
                      </div>
                    </header>
                  </article>
                ))}
              </div>
            )}
          </div>

          <div className="gl-cutover-block">
            <h3>检测到单用户占用端口 24000 的落地（{occupiedLandings.length}）</h3>
            {occupiedLandings.length === 0 ? (
              <p className="gl-context-copy">未发现被单用户 SS2022 占用的端口 24000 监听地址。</p>
            ) : (
              <div className="gl-pools-grid">
                {occupiedLandings.map((rt) =>
                  (rt.occupiedPort24000 ?? []).map((address) => {
                    const key = `${rt.id}/${address}`;
                    const inspected = cutoverPlans[key];
                    const plan = inspected?.plan;
                    const gate = canStartSocketCutover(inspected, rt.revision);
                    return (
                      <article key={key} className="gl-pool-card" data-cutover-target={key}>
                        <header className="gl-pool-card-header">
                          <div>
                            <h3>
                              {nodeName(rt.id)} · {address}:24000
                            </h3>
                            <p className="gl-context-copy">
                              {formatRevisionReceipt(rt.revision, rt.appliedRevision, rt.runtimeReady)} · 单用户端口 24000
                              需先检查全部消费方影响范围，再开启方案 A 受控切窗升级为多用户 EIH 24000。
                            </p>
                          </div>
                          <div className="gl-pool-card-actions">
                            <Button type="button" variant="outline" disabled={disabled} onClick={() => void inspectCutover(rt.id, address, rt.revision)}>
                              检查占用与影响范围
                            </Button>
                            <Button
                              type="button"
                              disabled={disabled || !gate.allowed}
                              title={gate.allowed ? "确认以上影响范围后开启受控切窗" : gate.reason}
                              onClick={async () => {
                                const ok = await save("socket-cutover", {
                                  action: "start",
                                  targetNodeId: rt.id,
                                  address,
                                  expectedTargetRevision: rt.revision,
                                  expectedScopeDigest: plan?.scopeDigest,
                                });
                                if (!ok) {
                                  const nextSeq = (inspectSeq.current[key] ?? 0) + 1;
                                  inspectSeq.current[key] = nextSeq;
                                  setCutoverPlans((prev) => ({
                                    ...prev,
                                    [key]: {
                                      seq: nextSeq,
                                      pending: false,
                                      invalidated: "启动切窗未确认，目标修订或受影响消费方范围可能已变化，请重新检查占用与影响范围后再试。",
                                    },
                                  }));
                                }
                              }}
                            >
                              开启 24000 切窗
                            </Button>
                          </div>
                        </header>
                        {!gate.allowed ? <p className="gl-context-copy">{gate.reason}</p> : null}
                        {inspected && plan ? (
                          <div className="gl-cutover-inspect-box" role="region" aria-label={`端口 24000 切窗影响范围 ${nodeName(rt.id)} ${address}`}>
                            <p className="gl-context-copy">
                              检查基准：目标修订 R{inspected.inspectedRevision} · 单用户占用：{plan.occupied ? "是" : "否"} · 可迁移消费方{" "}
                              {gate.migratableCount} 项（总关联 {plan.consumers.length} 项）
                              {plan.blockingConsumers.length > 0
                                ? ` · 阻塞节点：${plan.blockingConsumers.map(nodeName).join("、")}`
                                : " · 无阻塞项"}
                            </p>
                            {plan.consumers.length > 0 ? (
                              <ul className="gl-cutover-consumers">
                                {plan.consumers.map((c, idx) => (
                                  <li key={`${c.kind}:${c.entryId}:${c.peerKey ?? c.grantId ?? idx}`}>
                                    <strong>{nodeName(c.entryId)}</strong> · {cutoverConsumerKindLabel(c.kind)}
                                    {isCutoverConsumerMigratable(c.kind) ? "（随切窗迁移）" : ""}
                                    {c.source ? ` · 源 ${c.source}` : ""}
                                    {c.egressIp ? ` · 出口 ${c.egressIp}` : ""}
                                    {c.udp ? " · UDP" : ""}
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <p className="gl-context-copy">未检测到关联消费方。</p>
                            )}
                            {gate.allowed ? (
                              <>
                                <p className="gl-context-copy">
                                  切窗迁移范围：上述清单中的受影响消费方将在目标监听切换为多用户 EIH 24000 后，随推进切窗统一切换至新凭据。
                                </p>
                                <p className="gl-context-copy">
                                  进程重启影响：应用配置时会重启目标节点及上述入口节点上的整个 Glivela/Xray worker 进程，同一进程承载的其他无关线路（含直连或其他落地线路）的在途连接也可能发生短暂中断；切窗完成前请避免并发修改相关节点配置。
                                </p>
                              </>
                            ) : null}
                          </div>
                        ) : null}
                      </article>
                    );
                  }),
                )}
              </div>
            )}
          </div>
        </section>
      ) : null}

      {showPoolSheet ? (
        <Sheet open onOpenChange={(open) => { if (!open) setPoolEditorTarget(null); }}>
          <SheetContent className="gl-panel-sheet overflow-y-auto" data-standalone={standalone || undefined}>
            <SheetHeader>
              <SheetTitle>{poolEditorTarget?.mode === "create" ? "新增中转池" : `编辑中转池 · ${editingPool!.name}`}</SheetTitle>
              <SheetDescription>配置有序中转成员与 leastLoad 选路参数；保存仅写入期望配置，各节点生效以实际回执为准。</SheetDescription>
            </SheetHeader>
            <div className="gl-dialog-body">
              <RelayPoolEditor
                key={poolEditorTarget?.mode === "create" ? "create" : `edit:${editingPool!.id}`}
                inventory={inventory}
                names={names}
                initial={poolEditorTarget?.mode === "edit" ? editingPool ?? undefined : undefined}
                disabled={disabled}
                save={async (op, body) => {
                  const ok = await save(op, body);
                  if (ok) setPoolEditorTarget(null);
                  return ok;
                }}
              />
            </div>
          </SheetContent>
        </Sheet>
      ) : null}

      {editingEntry ? (
        <Sheet open onOpenChange={(open) => { if (!open) setEditingEntryId(null); }}>
          <SheetContent className="gl-panel-sheet overflow-y-auto" data-standalone={standalone || undefined}>
            <SheetHeader>
              <SheetTitle>入口探测与源地址 · {nodeName(editingEntry.id)}</SheetTitle>
              <SheetDescription>配置入口公网中转源地址及单进程 burstObservatory 探测参数（最小间隔 10 秒）。</SheetDescription>
            </SheetHeader>
            <div className="gl-dialog-body">
              <EntryObservatoryEditor
                key={editingEntry.id}
                entry={editingEntry}
                name={nodeName(editingEntry.id)}
                initialConfig={inventory.entryRelayConfigs?.[editingEntry.id]}
                disabled={disabled}
                save={async (op, body) => {
                  const ok = await save(op, body);
                  if (ok) setEditingEntryId(null);
                  return ok;
                }}
              />
            </div>
          </SheetContent>
        </Sheet>
      ) : null}
    </div>
  );
}
