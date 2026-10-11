import { createRoot } from "react-dom/client";
import type { Application } from "@/types";
import type { AppWorkspaceProps } from "@/app-workspaces/types";
import type { AppManagerProps } from "@/app-workspaces/types";
import { IPQualityProvider } from "@/views/IPQuality";
import { LandingProvider } from "@/views/LandingControls";
import { MeridianWorkspace } from "./meridian/Workspace";
import { MeridianManagerSheet } from "./meridian/Manager";
import { AppErrorBoundary } from "./AppErrorBoundary";
import "./style.css";

export const apiVersion = 1;

type MeridianHostProps = AppWorkspaceProps & {
  managerApplication?: Application | null;
  onManagerClose?: () => void;
};

// The app bundle owns the React tree. Center passes platform data and actions,
// but does not import or compile Glivela's page components.
export function mount(element: HTMLElement, initial: MeridianHostProps) {
  const root = createRoot(element);
  let props = initial;
  let localManager: Application | null = null;
  const render = () => root.render(
    <AppErrorBoundary language={props.language}><IPQualityProvider enabled agents={props.data.agents}>
      <LandingProvider enabled agents={props.data.agents}>
        <MeridianWorkspace {...props} onClients={(application) => {
          localManager = application;
          render();
        }} />
        <MeridianManagerSheet
          application={props.managerApplication ?? localManager}
          data={props.data}
          language={props.language}
          mutate={props.mutate}
          onClose={() => {
            localManager = null;
            props = { ...props, managerApplication: null };
            props.onManagerClose?.();
            render();
          }}
        />
      </LandingProvider>
    </IPQualityProvider></AppErrorBoundary>,
  );
  render();
  return {
    update(next: MeridianHostProps) {
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
    <AppErrorBoundary language={props.language}><LandingProvider enabled agents={props.data.agents}>
      <MeridianManagerSheet {...props} />
    </LandingProvider></AppErrorBoundary>,
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
