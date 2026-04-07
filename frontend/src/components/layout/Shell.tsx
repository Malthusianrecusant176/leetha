// frontend/src/components/layout/Shell.tsx
import { Sidebar } from "./Sidebar";
import type { WsStatus } from "@/hooks/use-websocket";

interface ShellProps {
  title: string;
  wsStatus: WsStatus;
  children: React.ReactNode;
}

export function Shell({ wsStatus, children }: ShellProps) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar wsStatus={wsStatus} />
      <main className="flex-1 flex flex-col overflow-y-auto p-6">{children}</main>
    </div>
  );
}
