import { useId, useState, type FormEvent } from "react";
import { ArrowDown, ArrowUp, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectControl } from "@/components/SelectControl";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import type {
  EntryRelayConfig,
  Inventory,
  ObservatoryConfig,
  RelayPoolMember,
  RelayPoolStrategy,
  RelayPoolView,
  Runtime,
} from "./control-types";
import {
  DEFAULT_OBSERVATORY_CONFIG,
  DEFAULT_POOL_STRATEGY,
  MAX_OBSERVATORY_INTERVAL_SEC,
  MIN_OBSERVATORY_INTERVAL_SEC,
  buildEntryRelayConfigPayload,
  buildRelayPoolChangePayload,
  effectiveEntryObservatory,
  formatRevisionReceipt,
  isZeroTimestamp,
  normalizeRelayPoolMember,
  validateObservatoryDraft,
  validatePoolDraft,
} from "./relay-pool-model";

export function RelayPoolEditor({
  inventory,
  names,
  initial,
  disabled,
  save,
}: {
  inventory: Inventory;
  names: Map<string, string>;
  initial?: RelayPoolView;
  disabled: boolean;
  save: (operation: string, body: unknown) => Promise<boolean>;
}) {
  const formID = useId();
  const isEdit = !!initial;
  const [baseRevision, setBaseRevision] = useState(initial?.revision ?? "0");
  const [poolId, setPoolId] = useState(initial?.id ?? "");
  const [name, setName] = useState(initial?.name ?? "");
  const [expected, setExpected] = useState(String(initial?.strategy.expected ?? DEFAULT_POOL_STRATEGY.expected));
  const [maxRttMs, setMaxRttMs] = useState(String(initial?.strategy.maxRttMs ?? DEFAULT_POOL_STRATEGY.maxRttMs));
  const [tolerance, setTolerance] = useState(String(initial?.strategy.tolerance ?? DEFAULT_POOL_STRATEGY.tolerance ?? 0.05));
  const [members, setMembers] = useState<RelayPoolMember[]>(() =>
    initial ? initial.members.map(normalizeRelayPoolMember) : [],
  );
  const [addNodeId, setAddNodeId] = useState("");
  const [error, setError] = useState("");
  const externalChanged = isEdit && !!initial && initial.revision !== baseRevision;

  const reloadLatestPool = () => {
    if (!initial) return;
    setBaseRevision(initial.revision);
    setName(initial.name);
    setExpected(String(initial.strategy.expected));
    setMaxRttMs(String(initial.strategy.maxRttMs));
    setTolerance(String(initial.strategy.tolerance ?? 0));
    setMembers(initial.members.map(normalizeRelayPoolMember));
    setError("");
  };

  const landings = inventory.runtimes.filter((rt) => rt.role === "landing" && !!rt.certificateId);
  const availableLandings = landings.filter((rt) => !members.some((m) => m.nodeId === rt.id));
  const nodeName = (id: string) => names.get(id) ?? id;

  const addMember = () => {
    const target = landings.find((rt) => rt.id === addNodeId);
    if (!target || !target.certificateId) return;
    const next: RelayPoolMember = {
      nodeId: target.id,
      certificateId: target.certificateId,
      ingressIpv4: target.publicIpv4 || undefined,
      ingressIpv6: target.publicIpv6 || undefined,
      egressIpv4: target.egressIp && !target.egressIp.includes(":") ? target.egressIp : target.publicIpv4 || undefined,
      egressIpv6: target.egressIp && target.egressIp.includes(":") ? target.egressIp : target.publicIpv6 || undefined,
    };
    setMembers((prev) => [...prev, next]);
    setAddNodeId("");
    setError("");
  };

  const updateMember = (index: number, patch: Partial<RelayPoolMember>) => {
    setMembers((prev) => prev.map((item, idx) => (idx === index ? { ...item, ...patch } : item)));
    setError("");
  };

  const moveMember = (index: number, delta: -1 | 1) => {
    const nextIndex = index + delta;
    if (nextIndex < 0 || nextIndex >= members.length) return;
    setMembers((prev) => {
      const copy = [...prev];
      const [item] = copy.splice(index, 1);
      copy.splice(nextIndex, 0, item);
      return copy;
    });
  };

  const removeMember = (index: number) => {
    setMembers((prev) => prev.filter((_, idx) => idx !== index));
    setError("");
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const strategy: RelayPoolStrategy = {
      expected: Number(expected),
      maxRttMs: Number(maxRttMs),
      tolerance: tolerance.trim() === "" ? 0 : Number(tolerance),
    };
    const draft = { id: poolId, name, strategy, members };
    const validationError = validatePoolDraft(draft);
    if (validationError) {
      setError(validationError);
      return;
    }
    setError("");
    await save(
      "relay-pools",
      buildRelayPoolChangePayload({
        id: poolId,
        name,
        revision: baseRevision,
        expectedRevision: baseRevision,
        strategy,
        members,
      }),
    );
  };

  return (
    <form className="gl-pool-form" onSubmit={(event) => void handleSubmit(event)}>
      <FieldGroup>
        {externalChanged && initial ? (
          <div className="gl-unsaved" role="status">
            <h3>检测到外部配置已更新</h3>
            <p>
              中转池当前修订已更新为 rev {initial.revision}（当前草稿基于 rev {baseRevision}）。您的未保存修改已保留；可重新加载最新配置，或按原基准版本提交由控制面校验冲突。
            </p>
            <div>
              <Button type="button" variant="outline" disabled={disabled} onClick={reloadLatestPool}>
                重新加载最新配置
              </Button>
            </div>
          </div>
        ) : null}
        <Field>
          <FieldLabel htmlFor={`${formID}-id`}>
            中转池 ID
            <Input
              id={`${formID}-id`}
              required
              readOnly={isEdit}
              disabled={disabled}
              placeholder="例如：pool-ap-east"
              value={poolId}
              onChange={(event) => {
                setPoolId(event.target.value);
                setError("");
              }}
            />
          </FieldLabel>
          <FieldDescription>稳定逻辑标识；创建后不可更改。名称修改不影响已有线路引用。</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor={`${formID}-name`}>
            显示名称
            <Input
              id={`${formID}-name`}
              required
              disabled={disabled}
              placeholder="例如：东亚中转池"
              value={name}
              onChange={(event) => {
                setName(event.target.value);
                setError("");
              }}
            />
          </FieldLabel>
        </Field>

        <fieldset className="gl-pool-fieldset">
          <legend>leastLoad 选路策略</legend>
          <p className="gl-context-copy">
            入口 Xray 使用单进程 burstObservatory 对池内已准入的完整路径探活，按 leastLoad 在期望并发数与 RTT 阈值内择优转发。
          </p>
          <div className="gl-pool-strategy-grid">
            <Field>
              <FieldLabel htmlFor={`${formID}-expected`}>
                期望并发节点数 (expected)
                <Input
                  id={`${formID}-expected`}
                  type="number"
                  min={1}
                  max={64}
                  step={1}
                  required
                  disabled={disabled}
                  value={expected}
                  onChange={(event) => setExpected(event.target.value)}
                />
              </FieldLabel>
            </Field>
            <Field>
              <FieldLabel htmlFor={`${formID}-max-rtt`}>
                最大参考 RTT (ms)
                <Input
                  id={`${formID}-max-rtt`}
                  type="number"
                  min={50}
                  max={30000}
                  step={10}
                  required
                  disabled={disabled}
                  value={maxRttMs}
                  onChange={(event) => setMaxRttMs(event.target.value)}
                />
              </FieldLabel>
            </Field>
            <Field>
              <FieldLabel htmlFor={`${formID}-tolerance`}>
                容差比例 (tolerance, 0-1)
                <Input
                  id={`${formID}-tolerance`}
                  type="number"
                  min={0}
                  max={1}
                  step={0.01}
                  disabled={disabled}
                  value={tolerance}
                  onChange={(event) => setTolerance(event.target.value)}
                />
              </FieldLabel>
            </Field>
          </div>
        </fieldset>

        <fieldset className="gl-pool-fieldset">
          <legend>中转成员（有序候选，共 {members.length} 个）</legend>
          <p className="gl-context-copy">
            成员顺序决定入口候选次序与首选兜底顺序；离线中转可直接移除，控制面会立即向受影响入口与下游落地提交撤销配置。
          </p>
          <div className="gl-pool-add-row">
            <SelectControl
              id={`${formID}-add-member`}
              aria-label="选择要加入中转池的落地节点"
              disabled={disabled || availableLandings.length === 0}
              value={addNodeId}
              onValueChange={setAddNodeId}
              placeholder={availableLandings.length ? "选择已登记的落地节点…" : "没有可新增的落地节点"}
              options={availableLandings.map((rt) => ({
                value: rt.id,
                label: `${nodeName(rt.id)}（${rt.runtimeReady ? "已应用" : "离线/待回执"}${rt.relayPoolCapable ? " · 支持 EIH" : ""}）`,
              }))}
            />
            <Button type="button" variant="outline" disabled={disabled || !addNodeId} onClick={addMember}>
              <Plus />
              加入成员
            </Button>
          </div>

          {members.length === 0 ? (
            <p className="gl-context-copy">当前没有成员；空池保存后会触发 Fail-Closed，绑定该池的线路将处于阻断状态且不会回退直连。</p>
          ) : (
            <ol className="gl-pool-member-editor-list">
              {members.map((member, index) => {
                const rt = landings.find((n) => n.id === member.nodeId);
                return (
                  <li key={member.nodeId} className="gl-pool-member-editor-card">
                    <div className="gl-pool-member-editor-head">
                      <div>
                        <strong>
                          #{index + 1} {nodeName(member.nodeId)}
                        </strong>
                        <small>
                          {rt ? formatRevisionReceipt(rt.revision, rt.appliedRevision, rt.runtimeReady) : "未找到运行时回执"}
                          {member.drained ? " · 成员已排空" : ""}
                        </small>
                      </div>
                      <div className="gl-pool-member-editor-actions">
                        <Button
                          type="button"
                          variant="outline"
                          disabled={disabled || index === 0}
                          aria-label={`上移 ${nodeName(member.nodeId)}`}
                          onClick={() => moveMember(index, -1)}
                        >
                          <ArrowUp />
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          disabled={disabled || index === members.length - 1}
                          aria-label={`下移 ${nodeName(member.nodeId)}`}
                          onClick={() => moveMember(index, 1)}
                        >
                          <ArrowDown />
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          disabled={disabled}
                          aria-label={`移除成员 ${nodeName(member.nodeId)}`}
                          onClick={() => removeMember(index)}
                        >
                          <X />
                        </Button>
                      </div>
                    </div>
                    <div className="gl-pool-member-ip-grid">
                      <Field>
                        <FieldLabel>
                          入站 IPv4 (24000)
                          <Input
                            disabled={disabled}
                            placeholder="例如：198.51.100.10"
                            value={member.ingressIpv4 ?? ""}
                            onChange={(event) => updateMember(index, { ingressIpv4: event.target.value })}
                          />
                        </FieldLabel>
                      </Field>
                      <Field>
                        <FieldLabel>
                          入站 IPv6 (24000)
                          <Input
                            disabled={disabled}
                            placeholder="例如：2001:db8::10"
                            value={member.ingressIpv6 ?? ""}
                            onChange={(event) => updateMember(index, { ingressIpv6: event.target.value })}
                          />
                        </FieldLabel>
                      </Field>
                      <Field>
                        <FieldLabel>
                          出站源 IPv4
                          <Input
                            disabled={disabled}
                            placeholder="例如：198.51.100.10"
                            value={member.egressIpv4 ?? ""}
                            onChange={(event) => updateMember(index, { egressIpv4: event.target.value })}
                          />
                        </FieldLabel>
                      </Field>
                      <Field>
                        <FieldLabel>
                          出站源 IPv6
                          <Input
                            disabled={disabled}
                            placeholder="例如：2001:db8::10"
                            value={member.egressIpv6 ?? ""}
                            onChange={(event) => updateMember(index, { egressIpv6: event.target.value })}
                          />
                        </FieldLabel>
                      </Field>
                    </div>
                    {member.drained ? (
                      <p className="gl-context-copy">
                        当前状态：成员排空{member.drainReason ? `（${member.drainReason}）` : ""}
                        {member.drainResumeAt && !isZeroTimestamp(member.drainResumeAt)
                          ? ` · 计划恢复 ${new Date(member.drainResumeAt).toLocaleString()}`
                          : " · 手动恢复"}
                      </p>
                    ) : null}
                  </li>
                );
              })}
            </ol>
          )}
        </fieldset>

        {error ? (
          <p role="alert" className="text-destructive">
            {error}
          </p>
        ) : null}
        <Button type="submit" disabled={disabled}>
          {isEdit ? "保存中转池配置" : "创建中转池"}
        </Button>
      </FieldGroup>
    </form>
  );
}

export function EntryObservatoryEditor({
  entry,
  name,
  initialConfig,
  disabled,
  save,
}: {
  entry: Runtime;
  name: string;
  initialConfig?: EntryRelayConfig;
  disabled: boolean;
  save: (operation: string, body: unknown) => Promise<boolean>;
}) {
  const formID = useId();
  const effective = effectiveEntryObservatory(entry.id, initialConfig ? { [entry.id]: initialConfig } : undefined);
  const latestConfigRevision = initialConfig?.revision ?? "0";
  const [baseEntryRevision, setBaseEntryRevision] = useState(entry.revision);
  const [baseConfigRevision, setBaseConfigRevision] = useState(latestConfigRevision);
  const [sourceIpv4, setSourceIpv4] = useState(initialConfig?.sourceIpv4 ?? "");
  const [sourceIpv6, setSourceIpv6] = useState(initialConfig?.sourceIpv6 ?? "");
  const [customObservatory, setCustomObservatory] = useState(effective.custom);
  const [destination, setDestination] = useState(effective.config.destination);
  const [intervalSec, setIntervalSec] = useState(String(effective.config.intervalSec));
  const [sampling, setSampling] = useState(String(effective.config.sampling));
  const [timeoutSec, setTimeoutSec] = useState(String(effective.config.timeoutSec));
  const [error, setError] = useState("");
  const externalChanged = entry.revision !== baseEntryRevision || latestConfigRevision !== baseConfigRevision;

  const reloadLatestConfig = () => {
    const nextEff = effectiveEntryObservatory(entry.id, initialConfig ? { [entry.id]: initialConfig } : undefined);
    setBaseEntryRevision(entry.revision);
    setBaseConfigRevision(latestConfigRevision);
    setSourceIpv4(initialConfig?.sourceIpv4 ?? "");
    setSourceIpv6(initialConfig?.sourceIpv6 ?? "");
    setCustomObservatory(nextEff.custom);
    setDestination(nextEff.config.destination);
    setIntervalSec(String(nextEff.config.intervalSec));
    setSampling(String(nextEff.config.sampling));
    setTimeoutSec(String(nextEff.config.timeoutSec));
    setError("");
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    let observatory: ObservatoryConfig | undefined;
    if (customObservatory) {
      observatory = {
        destination: destination.trim(),
        intervalSec: Number(intervalSec),
        sampling: Number(sampling),
        timeoutSec: Number(timeoutSec),
      };
      const validationError = validateObservatoryDraft(observatory);
      if (validationError) {
        setError(validationError);
        return;
      }
    }
    setError("");
    await save(
      "entry-observatory",
      buildEntryRelayConfigPayload(entry.id, baseEntryRevision, baseConfigRevision, {
        sourceIpv4: sourceIpv4.trim() || undefined,
        sourceIpv6: sourceIpv6.trim() || undefined,
        observatory,
      }),
    );
  };

  return (
    <form className="gl-pool-form" onSubmit={(event) => void handleSubmit(event)}>
      <FieldGroup>
        {externalChanged ? (
          <div className="gl-unsaved" role="status">
            <h3>检测到外部配置或节点修订已更新</h3>
            <p>
              服务端当前已更新为 R{entry.revision} / C{latestConfigRevision}（当前草稿基于 R{baseEntryRevision} / C{baseConfigRevision}
              ）。您的未保存输入已保留；可点击重新加载最新配置，或按原基准版本提交（由服务端 CAS 校验并发冲突）。
            </p>
            <div>
              <Button type="button" variant="outline" disabled={disabled} onClick={reloadLatestConfig}>
                重新加载最新配置
              </Button>
            </div>
          </div>
        ) : null}
        <div className="gl-readonly-field">
          <span>目标入口与回执状态</span>
          <p className="gl-context-copy">
            <strong>{name}</strong> · {formatRevisionReceipt(entry.revision, entry.appliedRevision, entry.runtimeReady)} · 草稿基准 R
            {baseEntryRevision} / C{baseConfigRevision}
            {entry.relayPoolCapable ? " · 支持中转池渲染" : " · 尚未上报中转池渲染能力"}
          </p>
        </div>

        <Field>
          <FieldLabel htmlFor={`${formID}-src4`}>
            显式公网源 IPv4（留空沿用入口默认监听地址）
            <Input
              id={`${formID}-src4`}
              disabled={disabled}
              placeholder={entry.publicIpv4 ? `当前默认：${entry.publicIpv4}` : "例如：198.51.100.2"}
              value={sourceIpv4}
              onChange={(event) => setSourceIpv4(event.target.value)}
            />
          </FieldLabel>
        </Field>
        <Field>
          <FieldLabel htmlFor={`${formID}-src6`}>
            显式公网源 IPv6（留空沿用入口默认监听地址）
            <Input
              id={`${formID}-src6`}
              disabled={disabled}
              placeholder={entry.publicIpv6 ? `当前默认：${entry.publicIpv6}` : "例如：2001:db8::2"}
              value={sourceIpv6}
              onChange={(event) => setSourceIpv6(event.target.value)}
            />
          </FieldLabel>
        </Field>

        <Field>
          <FieldLabel className="gl-toggle-label" htmlFor={`${formID}-custom-obs`}>
            自定义 burstObservatory 探测参数
            <input
              id={`${formID}-custom-obs`}
              className="gl-toggle"
              type="checkbox"
              role="switch"
              disabled={disabled}
              checked={customObservatory}
              onChange={(event) => {
                setCustomObservatory(event.target.checked);
                if (!event.target.checked) setError("");
              }}
            />
          </FieldLabel>
          <FieldDescription>
            关闭时使用默认配置（{DEFAULT_OBSERVATORY_CONFIG.destination}，间隔 {DEFAULT_OBSERVATORY_CONFIG.intervalSec}s，采样 {DEFAULT_OBSERVATORY_CONFIG.sampling} 次，超时 {DEFAULT_OBSERVATORY_CONFIG.timeoutSec}s）。探测参数属进程级配置，仅在入口存在池化三跳线路时激活。
          </FieldDescription>
        </Field>

        {customObservatory ? (
          <fieldset className="gl-pool-fieldset">
            <legend>入口 burstObservatory.pingConfig</legend>
            <Field>
              <FieldLabel htmlFor={`${formID}-dest`}>
                探测目标 URL
                <Input
                  id={`${formID}-dest`}
                  required
                  disabled={disabled}
                  value={destination}
                  onChange={(event) => setDestination(event.target.value)}
                />
              </FieldLabel>
            </Field>
            <div className="gl-pool-strategy-grid">
              <Field>
                <FieldLabel htmlFor={`${formID}-interval`}>
                  探测间隔（秒，{MIN_OBSERVATORY_INTERVAL_SEC}-{MAX_OBSERVATORY_INTERVAL_SEC}）
                  <Input
                    id={`${formID}-interval`}
                    type="number"
                    min={MIN_OBSERVATORY_INTERVAL_SEC}
                    max={MAX_OBSERVATORY_INTERVAL_SEC}
                    step={1}
                    required
                    disabled={disabled}
                    value={intervalSec}
                    onChange={(event) => setIntervalSec(event.target.value)}
                  />
                </FieldLabel>
              </Field>
              <Field>
                <FieldLabel htmlFor={`${formID}-sampling`}>
                  窗口采样次数 (1-10)
                  <Input
                    id={`${formID}-sampling`}
                    type="number"
                    min={1}
                    max={10}
                    step={1}
                    required
                    disabled={disabled}
                    value={sampling}
                    onChange={(event) => setSampling(event.target.value)}
                  />
                </FieldLabel>
              </Field>
              <Field>
                <FieldLabel htmlFor={`${formID}-timeout`}>
                  单次超时（秒，1-30）
                  <Input
                    id={`${formID}-timeout`}
                    type="number"
                    min={1}
                    max={30}
                    step={1}
                    required
                    disabled={disabled}
                    value={timeoutSec}
                    onChange={(event) => setTimeoutSec(event.target.value)}
                  />
                </FieldLabel>
              </Field>
            </div>
            <Button
              type="button"
              variant="outline"
              disabled={disabled}
              onClick={() => {
                setDestination(DEFAULT_OBSERVATORY_CONFIG.destination);
                setIntervalSec(String(DEFAULT_OBSERVATORY_CONFIG.intervalSec));
                setSampling(String(DEFAULT_OBSERVATORY_CONFIG.sampling));
                setTimeoutSec(String(DEFAULT_OBSERVATORY_CONFIG.timeoutSec));
                setError("");
              }}
            >
              填入默认探测参数
            </Button>
          </fieldset>
        ) : null}

        {error ? (
          <p role="alert" className="text-destructive">
            {error}
          </p>
        ) : null}
        <Button type="submit" disabled={disabled}>
          保存入口探测与源地址配置
        </Button>
      </FieldGroup>
    </form>
  );
}
