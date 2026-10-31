import { createContext, useContext, useMemo, type ReactNode } from "react";

type Request = <T>(operation: string, body: unknown, signal?: AbortSignal) => Promise<T>;
function client(applicationId?: string): Request {
  const base = applicationId ? `/api/v1/applications/${encodeURIComponent(applicationId)}/panel/v1/admin` : "/v1/admin";
  return async <T,>(operation: string, body: unknown, signal?: AbortSignal): Promise<T> => {
    if (!/^[a-z-]+$/.test(operation)) throw new Error("应用操作无效。");
    const headers = new Headers({ "Content-Type": "application/json" });
    if (applicationId) {
      const cookie = document.cookie.split(";").map(v => v.trim()).find(v => v.startsWith("vastora_csrf="));
      if (cookie) headers.set("X-CSRF-Token", decodeURIComponent(cookie.slice("vastora_csrf=".length)));
    }
    const response = await fetch(`${base}/${operation}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers, body: JSON.stringify(body), signal });
    if (!response.ok && operation === "link-speeds" && response.status === 409) { const code = (await response.text()).trim(); throw new Error(/^[a-z0-9_]{1,64}$/.test(code) ? code : "测速请求未确认，请刷新后再试。"); }
    if (!response.ok) {
      if (response.status === 409 && operation === "retire-entry") throw new Error("退役未确认：请检查入口是否离线、已暂停，链式监听是否已撤销并应用，以及是否有配置变更待处理。");
      if (response.status === 409 && (operation === "routes" || operation === "client-chains") && body && typeof body === "object" && "delete" in body && body.delete === true) throw new Error("删除未确认：请先停用线路，等待相关节点应用后再试。");
      if (response.status === 401) throw new Error("登录已过期，请重新登录 Vastora 后重试。");
      if (response.status === 403) throw new Error("当前身份没有此应用的管理权限。");
      if (response.status === 502 || response.status === 503) throw new Error("Glivela 暂时无法连接，或应用访问更新尚未完成。请稍后重试或查看应用更新状态。");
      throw new Error("操作未确认，请刷新实际状态后重试。");
    }
    return response.json() as Promise<T>;
  };
}
const Access = createContext<Request>(client());
export function ControlAccessProvider({ applicationId, children }: { applicationId: string; children: ReactNode }) {
  const request = useMemo(() => client(applicationId), [applicationId]);
  return <Access.Provider value={request}>{children}</Access.Provider>;
}
export const useControlRequest = () => useContext(Access);
