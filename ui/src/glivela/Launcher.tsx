import type { AppData } from "@/host-contract";
import type { Application } from "@/types";
import type { Language } from "@/translations";
import { Button } from "@/components/ui/button";
import { GlivelaControl } from "./Control";
import { ControlAccessProvider } from "./ControlAccess";

// The signed application UI is mounted directly. Center only provides the
// authenticated transport; Glivela remains the sole business backend.
export function GlivelaLauncher({ data, applications, language, onManage, onUpgrade }: {
  data: AppData; applications: Application[]; language: Language;
  onManage?: (application: Application) => void; onUpgrade?: (application: Application) => void;
}) {
  const zh = language === "zh-CN";
  const controllers = applications.filter(application => data.services.some(service => service.applicationId === application.id && service.name === "controller" && service.protocol === "https"));
  if (controllers.length === 1 && controllers[0].status === "running") {
    const application = controllers[0];
    return <ControlAccessProvider key={application.id} applicationId={application.id}><GlivelaControl /></ControlAccessProvider>;
  }
  return <section className="flex flex-col gap-3 p-4" data-app-workspace="vastora-official/meridian">
    <h1 className="text-xl font-semibold">Glivela</h1>
    <p role="status">{controllers.length > 1 ? (zh ? "检测到多个控制端，请在应用管理中核对安装关联。" : "Multiple controllers detected. Review the application installation.") : (zh ? "Glivela 控制端尚未就绪。" : "Glivela is not ready.")}</p>
    {applications.map(application => <div key={application.id} className="flex items-center gap-2"><span>{application.name}</span>{onManage ? <Button variant="outline" onClick={() => onManage(application)}>{zh ? "查看安装状态" : "Installation status"}</Button> : null}{onUpgrade && application.updateAvailable ? <Button onClick={() => onUpgrade(application)}>{zh ? "更新应用" : "Update application"}</Button> : null}</div>)}
  </section>;
}
