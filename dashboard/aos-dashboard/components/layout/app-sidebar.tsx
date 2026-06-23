"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  LayoutDashboard,
  ShieldAlert,
  Server,
  RotateCcw,
  Swords,
  BookOpen,
  UserCheck,
} from "lucide-react";
import { useSystemReset } from "@/hooks/useSystemReset";
import { useReviewQueue } from "@/hooks/useReviewQueue";
import { toast } from "sonner";

export function AppSidebar() {
  const pathname = usePathname();
  const resetMutation = useSystemReset();
  const { data: reviewQueue } = useReviewQueue();
  const pendingCount = reviewQueue?.length ?? 0;

  const items = [
    {
      title: "Dashboard",
      href: "/",
      icon: LayoutDashboard,
      badge: null,
    },
    {
      title: "Alerts",
      href: "/alerts",
      icon: ShieldAlert,
      badge: null,
    },
    {
      title: "Nodes",
      href: "/nodes",
      icon: Server,
      badge: null,
    },
    {
      title: "Attack Playbook",
      href: "/playbook",
      icon: BookOpen,
      badge: null,
    },
    {
      title: "Human Review",
      href: "/review",
      icon: UserCheck,
      badge: pendingCount > 0 ? pendingCount : null,
    },
    {
      title: "Simulate",
      href: "/#simulate",
      icon: Swords,
      badge: null,
    },
    {
      title: "Remediation Maps",
      href: "/remediations",
      icon: LayoutDashboard, // Will reuse LayoutDashboard icon to avoid missing imports
      badge: null,
    },
  ];

  const handleReset = async () => {
    if (
      !confirm(
        "Reset the entire Always-On Security environment?\n\nThis clears alerts, scores and investigation state.",
      )
    ) {
      return;
    }

    try {
      await resetMutation.mutateAsync();
      toast.success("System reset initiated");
    } catch {
      toast.error("System reset failed");
    }
  };

  return (
    <aside className="fixed left-0 top-0 z-50 flex h-screen w-64 flex-col border-r border-zinc-800 bg-zinc-950/95 backdrop-blur-md">
      {/* Logo */}
      <div className="border-b border-zinc-800 p-6">
        <h1 className="text-lg font-bold text-white">Always-On Security</h1>
        <p className="text-xs text-zinc-500">Security Operations Center</p>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3">
        <div className="space-y-1">
          {items.map((item) => {
            const Icon = item.icon;
            const active =
              pathname === item.href ||
              (item.href !== "/" && item.href !== "/#simulate" && pathname.startsWith(item.href));

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`
                  flex items-center gap-3 rounded-lg px-3 py-2 transition-colors
                  ${active
                    ? "bg-cyan-500/20 text-cyan-400"
                    : "text-zinc-400 hover:bg-zinc-900 hover:text-white"
                  }
                `}
              >
                <Icon size={18} />
                <span className="flex-1">{item.title}</span>
                {item.badge !== null && (
                  <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-amber-500 px-1.5 text-[10px] font-black text-zinc-950">
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      </nav>

      {/* Footer Status */}
      <div className="space-y-3 p-4">
        {pendingCount > 0 && (
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 animate-pulse rounded-full bg-amber-500" />
              <span className="text-sm font-semibold text-amber-300">
                {pendingCount} Node{pendingCount !== 1 ? "s" : ""} Pending Review
              </span>
            </div>
          </div>
        )}

        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
            <span className="text-sm text-zinc-300">Monitoring Active</span>
          </div>
        </div>

        <button
          onClick={handleReset}
          disabled={resetMutation.isPending}
          className="flex w-full items-center justify-center gap-2 rounded-lg border border-red-900 bg-red-500 px-3 py-2 text-sm text-white transition-colors hover:bg-red-900/40 disabled:opacity-50"
        >
          <RotateCcw size={16} />
          {resetMutation.isPending ? "Resetting..." : "Reset Environment"}
        </button>
      </div>
    </aside>
  );
}
