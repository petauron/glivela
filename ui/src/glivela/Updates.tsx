import { useState } from "react";
import type { AppWorkspaceProps } from "@/app-workspaces/types";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ApplicationPrimaryStatus, ApplicationUpdate } from "@/views/apps/InstalledApplicationPrimitives";
import { copy } from "@/views/shared";

export function GlivelaUpdates({ group, language, onUpgrade }: Pick<AppWorkspaceProps, "group" | "language" | "onUpgrade">) {
  const [open, setOpen] = useState(false);
  const instances = group.instances.filter((instance) => instance.application.updateAvailable || instance.activeChange?.operation === "upgrade");
  if (!instances.length) return null;
  return <Sheet open={open} onOpenChange={setOpen}>
    <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>{copy(language, "应用更新", "App updates")} · {instances.length}</Button>
    <SheetContent className="apps-workspace">
      <SheetHeader><SheetTitle>{copy(language, "Glivela 应用更新", "Glivela app updates")}</SheetTitle><SheetDescription>{copy(language, "更新各主机上的 Glivela 应用。", "Update Glivela on each host.")}</SheetDescription></SheetHeader>
      <div className="flex flex-col overflow-y-auto px-4">{instances.map((instance) => <div key={instance.application.id} className="flex items-center justify-between gap-3 border-b py-3">
        <div className="min-w-0"><p className="truncate font-medium">{instance.agent?.name ?? instance.application.nodeId}</p><p className="text-xs text-muted-foreground">{instance.application.installedVersion} → {instance.application.availableVersion}</p>{instance.activeChange ? <ApplicationPrimaryStatus instance={instance} language={language} /> : !instance.agent?.connected ? <p className="text-xs text-destructive">{copy(language, "离线", "Offline")}</p> : null}</div>
        <ApplicationUpdate instance={instance} language={language} onUpgrade={(application) => { setOpen(false); onUpgrade(application); }} />
      </div>)}</div>
    </SheetContent>
  </Sheet>;
}
