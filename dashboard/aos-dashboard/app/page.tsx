import { DashboardHeader } from "@/components/dashboard/dashboard-header";
import { StatCards } from "@/components/dashboard/stat-cards";
import { ThreatDistribution } from "@/components/dashboard/threat-distribution";
import { SeverityBreakdown } from "@/components/dashboard/severity-breakdown";
import { RecentEvents } from "@/components/dashboard/recent-events";
import { HighRiskNodes } from "@/components/dashboard/high-risk-nodes";

export default function DashboardPage() {
  return (
    <div className="relative min-h-screen bg-zinc-950">
      {/* Background Effects */}
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute left-0 top-0 h-96 w-96 rounded-full bg-blue-500/10 blur-3xl" />
        <div className="absolute right-0 top-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-96 w-96 rounded-full bg-purple-500/5 blur-3xl" />
      </div>

      <div className="mx-auto max-w-7xl p-8 space-y-8">
        {/* Header */}
        <DashboardHeader />

        {/* Title */}
        <div>
          <h1 className="text-4xl font-bold tracking-tight text-white">
            Security Operations Center
          </h1>

          <p className="mt-2 text-zinc-400">
            Always-On Security Monitoring Dashboard
          </p>
        </div>

        {/* Stat Cards */}
        <StatCards />

        {/* Charts */}
        <div className="grid gap-6 xl:grid-cols-2">
          <ThreatDistribution />
          <SeverityBreakdown />
        </div>

        {/* Events + Nodes */}
        <div className="space-y-6">
          <RecentEvents />
          <HighRiskNodes />
        </div>

        {/* Divider */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-zinc-800" />
          </div>
          <div className="relative flex justify-center">
            <span className="bg-zinc-950 px-4 text-xs font-medium uppercase tracking-widest text-zinc-600">
              Red Team Controls
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
