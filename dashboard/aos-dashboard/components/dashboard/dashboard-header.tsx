"use client";

import { Shield } from "lucide-react";

export function DashboardHeader() {
  return (
    <div
      className="
      flex
      items-center
      justify-between
      rounded-xl
      border
      border-zinc-800
      bg-zinc-900
      p-4
    "
    >
      <div className="flex items-center gap-3">
        <Shield className="text-cyan-500" />

        <div>
          <p className="font-semibold">Always-On Security</p>

          <p className="text-xs text-zinc-500">HPC Cluster Monitoring</p>
        </div>
      </div>

      <div className="text-green-500 text-sm">● Live</div>
    </div>
  );
}
