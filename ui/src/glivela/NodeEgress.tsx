import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { SelectControl } from "@/components/SelectControl";
import { useControlRequest } from "./ControlAccess";
import type { Runtime } from "./control-types";

type Policy = "auto" | "ipv4_only" | "ipv6_only";
type EgressView = {
  id: string; role: string; revision: string; runtimeReady: boolean;
  nativeEgress?: Policy; egressIp?: string; expectedExit?: string; linkedEntries: number;
  blockedPolicies?: Partial<Record<Policy, string>>; readOnlyReason?: string;
};
const policies = [
  { value: "ipv4_only", label: "仅 IPv4" },
  { value: "ipv6_only", label: "仅 IPv6" },
  { value: "auto", label: "自动（IPv4 / IPv6）" },
] as const;
const egressErrors: Record<string, string> = {
  egress_unavailable: "当前节点的出口配置不可用，请刷新状态后重试。",
  egress_transition_pending: "节点有尚未完成的配置切换，请先完成该操作。",
  egress_revision_changed: "节点配置已变化，请重新读取后选择，未覆盖其他更改。",
  egress_invalid_policy: "出口策略未通过现有安全校验，配置未保存。",
  egress_invalid_address: "请输入本机已分配的有效 IPv4 或 IPv6 地址。",
  egress_expected_exit_required: "关联线路的公网出口信息无效或与绑定地址族不匹配，请先核对既有线路；NAT 地址不能代替公网出口。",
  egress_ipv6_chain_conflict: "已有启用的 IPv6 客户端链，当前不能选择仅 IPv4；请先调整关联链路。",
  egress_ipv4_chain_conflict: "已有启用的 IPv4 客户端链，当前不能选择仅 IPv6；请先调整关联链路。",
  egress_chain_unverified: "关联客户端链配置尚未确认，暂不能修改出口策略。",
  egress_udp_conflict: "该落地仍有 UDP 授权，不能直接切换到仅支持 TCP 的 IPv6 出口。",
  egress_bound_exit_conflict: "该落地被现有服务端线路绑定，不能在此单独切换公网出口；当前配置未修改。",
  egress_route_conflict: "关联线路与新出口不匹配，配置未保存，请先核对线路。",
  egress_projection_pending: "有待完成的业务配置变更，请刷新状态并待其完成后重试。",
};

export function NodeEgress({ node, disabled, onSaved }: { node: Runtime; disabled: boolean; onSaved: () => Promise<void> }) {
  const manage = useControlRequest();
  const id = useId();
  const [view, setView] = useState<EgressView>();
  const [policy, setPolicy] = useState<Policy>("ipv4_only");
  const [address, setAddress] = useState("");
  const [expectedExit, setExpectedExit] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const pending = useRef(false);
  const loadSequence = useRef(0);
  const accept = useCallback((next: EgressView) => {
    setView(next); setPolicy(next.nativeEgress ?? "ipv4_only");
    setAddress(next.egressIp ?? ""); setExpectedExit(next.expectedExit ?? "");
  }, []);
  const load = useCallback(async (signal?: AbortSignal) => {
    const sequence = ++loadSequence.current;
    setLoading(true); setError("");
    try { const next = await manage<EgressView>("node-egress", { id: node.id, action: "inspect" }, signal); if (!signal?.aborted && sequence === loadSequence.current) accept(next); }
    catch (failure) { if (!signal?.aborted && sequence === loadSequence.current) { setView(undefined); setError(failure instanceof Error ? egressErrors[failure.message] ?? failure.message : "出口配置读取失败。"); } }
    finally { if (!signal?.aborted && sequence === loadSequence.current) setLoading(false); }
  }, [manage, node.id, accept]);
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => { controller.abort(); loadSequence.current++; };
  }, [load, node.revision]);
  const entry = view?.role === "entry";
  const reason = view?.readOnlyReason || (entry ? view.blockedPolicies?.[policy] : "");
  const changed = !!view && (entry ? policy !== view.nativeEgress : address.trim() !== view.egressIp || expectedExit.trim() !== (view.expectedExit ?? ""));
  const locked = disabled || loading || saving || !!view?.readOnlyReason;
  const ready = view?.runtimeReady;
  return <form className="gl-egress-form w-full max-w-xl" aria-label={`${node.role === "entry" ? "线路端" : "落地端"}出口选择`} aria-busy={loading || saving} onSubmit={async event => {
    event.preventDefault();
    if (!view || locked || !changed || reason || pending.current) return;
    pending.current = true; const sequence = ++loadSequence.current; setSaving(true); setError(""); setNotice("");
    try {
      const next = await manage<EgressView>("node-egress", { id: node.id, action: "apply", expectedRevision: view.revision, ...(entry ? { nativeEgress: policy } : { egressIp: address.trim(), ...(view.linkedEntries ? { expectedExit: expectedExit.trim() } : {}) }) });
      if (sequence === loadSequence.current) accept(next);
      setNotice("出口配置已保存，等待节点应用；实际访问仍需验证。");
      try { await onSaved(); } catch { setNotice("出口配置已保存；节点状态刷新失败，请点击刷新状态核对应用结果。"); }
    } catch (failure) { setError(failure instanceof Error ? egressErrors[failure.message] ?? failure.message : "出口修改未确认，请重新读取状态。"); }
    finally { pending.current = false; setSaving(false); }
  }}><FieldGroup>
    <div className="gl-overview-actions"><h4>出口选择</h4><Button type="button" variant="ghost" size="sm" disabled={loading || saving} onClick={() => void load()}>重新读取</Button></div>
    {loading ? <p role="status" className="gl-secondary">正在读取出口配置…</p> : null}
    {view ? <>
      {entry ? <Field data-disabled={locked} data-invalid={!!reason && changed}>
        <FieldLabel htmlFor={`${id}-policy`}>直连出口地址族</FieldLabel>
        <SelectControl id={`${id}-policy`} aria-label="直连出口地址族" aria-describedby={`${id}-hint`} aria-invalid={!!reason && changed} disabled={locked} value={policy} onValueChange={value => { setPolicy(value as Policy); setNotice(""); setError(""); }} options={policies.map(option => ({ ...option, disabled: !!view.blockedPolicies?.[option.value], label: `${option.label}${view.blockedPolicies?.[option.value] ? "（关联链路限制）" : ""}` }))}/>
        <FieldDescription id={`${id}-hint`}>普通直连可选仅 IPv4，需要 IPv6 出口时单独选择。此设置与客户端连接入口时使用的地址族不同。</FieldDescription>
        {Object.values(view.blockedPolicies ?? {}).map(code => <p key={code} className="gl-secondary">{egressErrors[code]}</p>)}
      </Field> : <>
        <Field data-disabled={locked}><FieldLabel htmlFor={`${id}-address`}>落地绑定出口地址</FieldLabel><Input id={`${id}-address`} aria-describedby={`${id}-address-hint`} required maxLength={45} disabled={locked} value={address} onChange={event => { setAddress(event.target.value); setNotice(""); setError(""); }}/><FieldDescription id={`${id}-address-hint`}>填写本机网卡已分配的 IPv4 或 IPv6 地址；地址族决定落地出口。NAT 主机填写本机绑定地址。</FieldDescription></Field>
        {view.linkedEntries > 0 ? <Field data-disabled={locked}><FieldLabel htmlFor={`${id}-expected`}>实际公网出口 IP</FieldLabel><Input id={`${id}-expected`} readOnly value={expectedExit}/><FieldDescription>{view.linkedEntries} 个服务端入口已绑定此公网出口。当前仅可调整仍使用相同公网出口的本机绑定地址，不能在此切换地址族或公网 IP；已有线路保持不变。</FieldDescription></Field> : null}
      </>}
      {view.readOnlyReason ? <p role="status">{egressErrors[view.readOnlyReason]}</p> : null}
      <p className="gl-secondary">当前已保存：{entry ? policies.find(option => option.value === view.nativeEgress)?.label : `${view.egressIp?.includes(":") ? "IPv6" : "IPv4"} · ${view.egressIp}`} · 修订 {view.revision} · 本次读取：{ready ? "节点已应用" : "节点尚未确认应用"}</p>
      <div><Button type="submit" disabled={locked || !changed || !!reason || !entry && (!address.trim() || view.linkedEntries > 0 && !expectedExit.trim())}>{saving ? "正在保存…" : "保存出口选择"}</Button></div>
    </> : null}
    {error ? <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert> : null}
    {notice ? <p role="status">{notice}</p> : null}
  </FieldGroup></form>;
}
