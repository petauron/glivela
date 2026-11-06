import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useControlRequest } from "./ControlAccess";

type Item = { id: string; name: string; kind: string; protocol: string };
type OrderView = { revision: string; inventory: string; available: boolean; items: Item[] };
type Props = { accountId: string; active: boolean; disabled: boolean; onDirtyChange: (dirty: boolean) => void; save: (operation: string, body: unknown) => Promise<boolean> };
const kindLabel: Record<string, string> = { native: "直连", route: "服务端转发", chain: "客户端链式" };
const sameOrder = (left: Item[], right: Item[]) => left.length === right.length && left.every((item, index) => item.id === right[index].id);

export function SubscriptionOrderEditor({ accountId, active, disabled, onDirtyChange, save }: Props) {
  const request = useControlRequest();
  const [view, setView] = useState<OrderView>();
  const [draft, setDraft] = useState<Item[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const loaded = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true); setError("");
    try {
      const result = await request<OrderView>("subscription-order", { accountId }, signal);
      if (signal?.aborted || !mounted.current) return;
      setView(result); setDraft(result.items); loaded.current = true;
      setAnnouncement(""); onDirtyChange(false);
    } catch (failure) {
      if (!signal?.aborted && mounted.current) setError(failure instanceof Error ? failure.message : "订阅顺序读取失败。");
    } finally {
      if (!signal?.aborted && mounted.current) setLoading(false);
    }
  }, [request, accountId, onDirtyChange]);
  useEffect(() => {
    if (!active || loaded.current) return;
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [active, load]);
  const changed = !!view && !sameOrder(draft, view.items);
  const blocked = disabled || loading;
  const move = (index: number, direction: number) => {
    const nextIndex = index + direction;
    if (blocked || !view || nextIndex < 0 || nextIndex >= draft.length) return;
    const next = draft.slice();
    [next[index], next[nextIndex]] = [next[nextIndex], next[index]];
    setDraft(next); onDirtyChange(!sameOrder(next, view.items));
    setAnnouncement(`${draft[index].name} 已移至第 ${nextIndex + 1} 项。`);
  };
  const commit = async () => {
    if (blocked || !changed || !view) return;
    const saved = await save("subscription-order", { accountId, expectedRevision: view.revision, inventory: view.inventory, ids: draft.map(item => item.id) });
    if (saved && mounted.current) await load();
  };
  return <section className="gl-subscription-order" aria-label="订阅排序">
    <h3>订阅排序</h3>
    <p>调整本账户代理顺序并保存，OpenClash 刷新订阅后生效。仅列出当前可发布代理；暂不可发布项保留已保存的位置。新增直连排在现有直连之后；没有现有直连时排在最前，其他新增代理排在末尾。</p>
    {error ? <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert> : null}
    {loading ? <p role="status">正在读取订阅代理…</p> : view && !view.available ? <p>暂无可排序的已发布代理，请核对账户和线路状态后重新读取。</p> : null}
    <ol className="gl-subscription-order-list" aria-label="OpenClash 代理顺序" aria-busy={loading}>
      {draft.map((item, index) => <li key={item.id}>
        <span className="gl-subscription-position" aria-hidden="true">{index + 1}</span>
        <div className="gl-subscription-label"><strong>{item.name}</strong><small>{kindLabel[item.kind] ?? item.kind}</small></div>
        <div className="gl-subscription-order-actions">
          <Button type="button" variant="ghost" size="icon" aria-label={`上移 ${item.name}`} disabled={blocked || index === 0} onClick={() => move(index, -1)}><ArrowUp aria-hidden="true"/></Button>
          <Button type="button" variant="ghost" size="icon" aria-label={`下移 ${item.name}`} disabled={blocked || index === draft.length - 1} onClick={() => move(index, 1)}><ArrowDown aria-hidden="true"/></Button>
        </div>
      </li>)}
    </ol>
    <p className="sr-only" role="status" aria-live="polite">{announcement}</p>
    <div className="gl-subscription-order-footer">
      <Button type="button" disabled={blocked || !changed} onClick={() => void commit()}>保存顺序</Button>
      <Button type="button" variant="outline" disabled={blocked} onClick={() => void load()}>{changed ? "重新读取并放弃更改" : "重新读取"}</Button>
    </div>
  </section>;
}
