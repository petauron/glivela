import type { AppData } from "@/host-contract";
import type { Application } from "@/types";
import type { Language } from "@/translations";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";

// The host supplies installation metadata only. It does not authenticate or
// proxy business requests. Opening the private controller preserves end-to-end
// administrator mTLS; a TLS-terminating host iframe/proxy cannot substitute it.
export function GlivelaLauncher({ data, applications, language, onManage, onUpgrade }: {
  data: AppData;
  applications: Application[];
  language: Language;
  onManage?: (application: Application) => void;
  onUpgrade?: (application: Application) => void;
}) {
  const zh = language === "zh-CN";
  const controllers = applications.flatMap(application => {
    const service = data.services.find(item => item.applicationId === application.id && item.name === "controller" && item.protocol === "https");
    if (!service) return [];
    let url: URL;
    try { url = new URL(`https://${service.endpoint}`); } catch { return []; }
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") return [];
    return [{ application, service, url: url.href }];
  });
  return <section data-app-workspace="vastora-official/meridian" className="flex flex-col gap-4 p-4 sm:p-6">
    <header><h1 className="text-xl font-semibold">Glivela</h1><p className="text-sm text-muted-foreground">{zh ? "账户、订阅、线路和健康状态由独立 Glivela 控制端管理。" : "Accounts, subscriptions, routes and health are managed by the independent Glivela controller."}</p></header>
    <Alert><AlertDescription>{zh ? "Vastora 仅管理应用安装、更新和卸载。打开控制端需连接私网并使用已登记的 Glivela 管理证书；不会转发 Vastora 登录凭据。" : "Vastora manages installation, updates and removal only. The controller requires private-network access and an enrolled Glivela administrator certificate; Vastora credentials are not forwarded."}</AlertDescription></Alert>
    {controllers.length === 0 ? <p role="status">{zh ? "Glivela 控制端尚不可用，请先完成应用安装及已有数据接管。" : "Glivela controller unavailable. Complete installation and existing-data handover first."}</p> : controllers.map(({ application, service, url }) => <article key={application.id} className="flex flex-col gap-3">
      <h2 className="font-medium">{application.name}</h2>
      <p className="text-sm text-muted-foreground">{application.installedVersion ?? "—"} · {zh ? "安装状态（非线路验证）" : "Installation state (not route verification)"}: {application.status}</p>
      <div className="flex flex-wrap gap-2">
        {application.status === "running" && service.status === "ready" ? <a className={buttonVariants()} href={url} target="_blank" rel="noopener noreferrer">{zh ? "打开 Glivela（新窗口）" : "Open Glivela (new window)"}</a> : <p role="status">{zh ? "控制端安装尚未就绪，不使用历史成功状态代替核验。" : "Controller installation is not ready; historical success is not current verification."}</p>}
        {onManage ? <Button variant="outline" onClick={() => onManage(application)}>{zh ? "管理安装" : "Manage installation"}</Button> : null}
        {onUpgrade && application.updateAvailable ? <Button variant="outline" onClick={() => onUpgrade(application)}>{zh ? "更新应用" : "Update application"}</Button> : null}
      </div>
    </article>)}
  </section>;
}
