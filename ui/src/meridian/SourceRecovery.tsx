import { useState } from "react";
import { ShieldCheckIcon } from "lucide-react";
import { api } from "@/api";
import type { MeridianSourceRecovery } from "@/meridian-types";
import type { Language } from "@/translations";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { copy } from "@/views/shared";

export function SourceRecovery({ endpointId, language, busy, onRun }: {
  endpointId: string;
  language: Language;
  busy: string;
  onRun: (key: string, operation: () => Promise<unknown>, success: string) => Promise<void>;
}) {
  const [evidence, setEvidence] = useState<MeridianSourceRecovery | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [queued, setQueued] = useState(false);
  const key = `source-recovery-${endpointId}`;
  const inspect = () => {
    setEvidence(null);
    setConfirmed(false);
    void onRun(key, async () => setEvidence(await api.meridianSourceRecovery(endpointId)), "");
  };
  const recover = () => {
    if (!evidence || !confirmed || busy) return;
    const reviewed = evidence;
    void onRun(key, async () => {
      try {
        await api.recoverMeridianSource(endpointId, reviewed);
        setQueued(true);
      } finally {
        // A conflict must require a new review, never a repeat of stale evidence.
        setEvidence(null);
        setConfirmed(false);
      }
    }, copy(language, "身份已确认，正在恢复落地授权与线路。", "Identity confirmed. Restoring landing authorization and routes."));
  };

  return <details className="mt-4">
    <summary className="w-fit cursor-pointer text-sm font-medium">{copy(language, "重装后恢复落地线路", "Restore landing routes after reinstall")}</summary>
    <div className="mt-3 flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">{copy(language, "保留现有账号和订阅。先检查新身份，再确认恢复；线路通过落地授权和连通性验证后才会就绪。", "Keeps existing accounts and subscriptions. Inspect the replacement identity, then confirm recovery. Routes become ready only after landing authorization and connectivity are verified.")}</p>
      {queued ? <p role="status" className="text-sm">{copy(language, "恢复已提交，请在节点列表查看线路状态。", "Recovery submitted. Check route status in the node list.")}</p> : null}
      {!evidence && !queued ? <Button className="self-start" disabled={Boolean(busy)} onClick={inspect} size="sm" type="button" variant="outline">{busy === key ? <Spinner data-icon="inline-start" /> : null}{copy(language, "检查重装身份", "Inspect replacement identity")}</Button> : null}
      {evidence ? <Alert>
        <ShieldCheckIcon />
        <AlertTitle>{copy(language, "检测到新的私网身份", "Replacement private identity detected")}</AlertTitle>
        <AlertDescription>
          <dl className="grid gap-2 text-xs sm:grid-cols-2">
            <div><dt>{copy(language, "原身份", "Previous identity")}</dt><dd className="font-mono">{evidence.previousAddress} · {evidence.previousFingerprint.slice(0, 12)}</dd></div>
            <div><dt>{copy(language, "新身份", "New identity")}</dt><dd className="font-mono">{evidence.currentAddress} · {evidence.currentFingerprint.slice(0, 12)}</dd></div>
          </dl>
          <Field className="mt-3" orientation="horizontal">
            <FieldLabel htmlFor={`${key}-confirm`}>{copy(language, "确认这是重装后的节点，原节点与旧任务已停止", "This is the reinstalled node; the previous node and tasks have stopped")}</FieldLabel>
            <Switch id={`${key}-confirm`} checked={confirmed} disabled={Boolean(busy)} onCheckedChange={setConfirmed} />
          </Field>
          <Button className="mt-3" disabled={!confirmed || Boolean(busy)} onClick={recover} size="sm" type="button">{busy === key ? <Spinner data-icon="inline-start" /> : null}{copy(language, "确认身份并恢复线路", "Confirm identity and restore routes")}</Button>
        </AlertDescription>
      </Alert> : null}
    </div>
  </details>;
}
