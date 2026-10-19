import { createRoot } from "react-dom/client";
import type { Application } from "@/types";
import type { AppWorkspaceProps } from "@/app-workspaces/types";
import type { AppManagerProps } from "@/app-workspaces/types";
import { GlivelaLauncher } from "./glivela/Launcher";
import { AppErrorBoundary } from "./AppErrorBoundary";
import "./style.css";
import { GlivelaControl } from "./glivela/Control";

// Served by Glivela itself behind its existing management mTLS listener.
export function mountControl(element: HTMLElement) {
  const root = createRoot(element);
  root.render(<AppErrorBoundary language="zh-CN"><GlivelaControl /></AppErrorBoundary>);
  return { unmount: () => root.unmount() };
}

export const apiVersion = 1;

type GlivelaHostProps = AppWorkspaceProps & {
  managerApplication?: Application | null;
  onManagerClose?: () => void;
};

// The host mounts only an installation launcher. Business UI/API are served
// directly by Glivela and never use the host session, SSE or task broker.
export function mount(element: HTMLElement, initial: GlivelaHostProps) {
  const root = createRoot(element);
  let props = initial;
  const render = () => root.render(
    <AppErrorBoundary language={props.language}><GlivelaLauncher data={props.data} language={props.language} applications={props.group.controller ? [props.group.controller.application, ...props.group.instances.filter(instance => instance.application.id !== props.group.controller?.application.id).map(instance => instance.application)] : props.group.instances.map(instance => instance.application)} onManage={props.onManage} onUpgrade={props.onUpgrade} /></AppErrorBoundary>,
  );
  render();
  return {
    update(next: GlivelaHostProps) {
      props = next;
      render();
    },
    unmount() {
      root.unmount();
    },
  };
}

export function mountManager(element: HTMLElement, initial: AppManagerProps) {
  const root = createRoot(element);
  let props = initial;
  const render = () => root.render(
    <AppErrorBoundary language={props.language}>{props.application ? <GlivelaLauncher data={props.data} language={props.language} applications={props.data.applications.filter(application => application.appKey === props.application?.appKey)} /> : null}</AppErrorBoundary>,
  );
  render();
  return {
    update(next: AppManagerProps) {
      props = next;
      render();
    },
    unmount() {
      root.unmount();
    },
  };
}
