import { AppSidebar } from "./app-sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-zinc-950">
      <AppSidebar />

      <main className="ml-64 min-h-screen">{children}</main>
    </div>
  );
}
