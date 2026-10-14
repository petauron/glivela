import { Component, type ErrorInfo, type ReactNode } from "react";

export class AppErrorBoundary extends Component<{ children: ReactNode; language: "zh-CN" | "en" }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (import.meta.env.DEV) console.error("Glivela interface failed", error, info.componentStack);
  }

  render() {
    if (this.state.failed) {
      return <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
        {this.props.language === "zh-CN" ? "Glivela 界面暂时无法显示。请重新打开应用页面。" : "Glivela could not be displayed. Reopen the application page."}
      </div>;
    }
    return this.props.children;
  }
}
