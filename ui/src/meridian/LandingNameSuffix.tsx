import { useId, useState } from "react";
import type { Language } from "@/translations";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { copy } from "@/views/shared";

export function LandingNameSuffix({ language, value, disabled, save }: { language: Language; value: string; disabled: boolean; save: (suffix: string) => Promise<boolean> }) {
  const id = useId();
  const [draft, setDraft] = useState(value);
  const suffix = draft.trim();
  return <form className="grid gap-1.5 text-xs" onSubmit={(event) => { event.preventDefault(); if (!disabled && suffix !== value) void save(suffix); }}>
    <label htmlFor={id}>{copy(language, "订阅名称后缀（可选）", "Subscription name suffix (optional)")}</label>
    <div className="flex items-center gap-2"><Input id={id} value={draft} onChange={(event) => setDraft(event.target.value)} disabled={disabled} placeholder="ATT / BGP" aria-describedby={`${id}-hint`} /><Button type="submit" size="sm" variant="outline" disabled={disabled || suffix === value}>{copy(language, "保存后缀", "Save suffix")}</Button></div>
    <p id={`${id}-hint`} className="text-muted-foreground">{copy(language, `显示为“落地${suffix}”，留空不添加后缀。`, `Shown as “落地${suffix}”; leave blank for no suffix.`)}</p>
  </form>;
}
