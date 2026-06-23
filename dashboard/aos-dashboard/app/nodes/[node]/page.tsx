"use client";

import { use } from "react";

import { Card } from "@/components/ui/card";

import { useNodeDetails } from "@/hooks/useNodeDetails";
import { useNodeIdentity } from "@/hooks/useNodeIdentity";
import { useNodeSecurity } from "@/hooks/useNodeSecurity";
import { useIncidentSummary } from "@/hooks/useIncidentSummary";

import { ForensicPanel } from "@/components/review/incident-card";

import { NodeTimeline } from "@/components/nodes/node-timeline";
import { RulesCard } from "@/components/nodes/rules-card";
import { RiskTrend } from "@/components/nodes/risk-trend";
import { ReasonsCard } from "@/components/nodes/reasons-card";
import { NodeActions } from "@/components/nodes/node-actions";

export default function NodeDetailsPage({
  params,
}: {
  params: Promise<{
    node: string;
  }>;
}) {
  const { node } = use(params);

  const { data: history, isLoading, error } = useNodeDetails(node);

  const { data: identity } = useNodeIdentity(node);
  const { data: security } = useNodeSecurity(node);
  const { data: incidentSummary } = useIncidentSummary(node);

  if (isLoading) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <Card className="border-zinc-800 bg-zinc-900 p-6 text-white">
          Loading node details...
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto max-w-7xl p-8">
        <Card className="border-zinc-800 bg-zinc-900 p-6 text-red-400">
          Failed to load node details.
        </Card>
      </div>
    );
  }

  const rules = Array.from(
    new Set(history?.flatMap((event: any) => event.matched_rules ?? []) ?? []),
  ) as string[];

  const reasons = Array.from(
    new Set(history?.flatMap((event: any) => event.reasons ?? []) ?? []),
  ) as string[];

  return (
    <div className="relative min-h-screen bg-zinc-950">
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute left-0 top-0 h-96 w-96 rounded-full bg-red-500/10 blur-3xl" />
        <div className="absolute right-0 top-0 h-96 w-96 rounded-full bg-orange-500/10 blur-3xl" />
      </div>

      <div className="mx-auto max-w-7xl space-y-6 p-8">
        {/* HEADER */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white">{node}</h1>

            <p className="mt-2 text-zinc-400">Security Investigation View</p>

            <div className="mt-3 flex gap-4 text-sm">
              <span className="text-zinc-400">
                Status:
                <span className="ml-2 font-medium text-white">
                  {security?.status ?? "Unknown"}
                </span>
              </span>

              <span className="text-zinc-400">
                Trust:
                <span className="ml-2 font-medium text-amber-400">
                  {identity?.trust_status ?? "Unknown"}
                </span>
              </span>
            </div>
          </div>

          <NodeActions node={node} status={security?.status} />
        </div>

        {/* CURRENT SECURITY STATE */}
        <div className="grid gap-6 md:grid-cols-4">
          <Card className="border-zinc-800 bg-zinc-900 p-6">
            <div className="text-sm text-zinc-500">Current Risk Score</div>

            <div className="mt-2 text-4xl font-bold text-red-400">
              {security?.risk_score ?? 0}
            </div>
          </Card>

          <Card className="border-zinc-800 bg-zinc-900 p-6">
            <div className="text-sm text-zinc-500">Current Status</div>

            <div className="mt-2 text-3xl font-bold text-cyan-400">
              {security?.status ?? "Unknown"}
            </div>
          </Card>

          <Card className="border-zinc-800 bg-zinc-900 p-6">
            <div className="text-sm text-zinc-500">Trust Status</div>

            <div className="mt-2 text-3xl font-bold text-amber-400">
              {identity?.trust_status ?? "Unknown"}
            </div>
          </Card>

          <Card className="border-zinc-800 bg-zinc-900 p-6">
            <div className="text-sm text-zinc-500">Silent Events</div>

            <div className="mt-2 text-4xl font-bold text-orange-400">
              {security?.silent_count ?? 0}
            </div>
          </Card>
        </div>

        {/* SECURITY METRICS */}
        <div>
          <h2 className="mb-4 text-xl font-semibold text-white">
            Security Metrics
          </h2>

          <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-5">
            <Card className="border-zinc-800 bg-zinc-900 p-6">
              <div className="text-sm text-zinc-500">Silent Events</div>

              <div className="mt-2 text-4xl font-bold text-orange-400">
                {security?.silent_count ?? 0}
              </div>
            </Card>

            <Card className="border-zinc-800 bg-zinc-900 p-6">
              <div className="text-sm text-zinc-500">Flood Attacks</div>

              <div className="mt-2 text-4xl font-bold text-red-400">
                {security?.flood_count ?? 0}
              </div>
            </Card>

            <Card className="border-zinc-800 bg-zinc-900 p-6">
              <div className="text-sm text-zinc-500">Replay Attempts</div>

              <div className="mt-2 text-4xl font-bold text-yellow-400">
                {security?.replay_count ?? 0}
              </div>
            </Card>

            <Card className="border-zinc-800 bg-zinc-900 p-6">
              <div className="text-sm text-zinc-500">Config Tampering</div>

              <div className="mt-2 text-4xl font-bold text-purple-400">
                {security?.config_tamper_count ?? 0}
              </div>
            </Card>

            <Card className="border-zinc-800 bg-zinc-900 p-6">
              <div className="text-sm text-zinc-500">Lateral Movement</div>

              <div className="mt-2 text-4xl font-bold text-cyan-400">
                {security?.lateral_movement_count ?? 0}
              </div>
            </Card>
          </div>
        </div>

        {/* NODE IDENTITY */}
        <Card className="border-zinc-800 bg-zinc-900 p-6">
          <h2 className="mb-6 text-lg font-semibold text-white">
            Node Identity
          </h2>

          <div className="grid gap-6 md:grid-cols-3">
            <div>
              <div className="text-xs uppercase tracking-wide text-zinc-500">
                Machine ID
              </div>

              <div className="mt-2 break-all font-mono text-sm text-zinc-300">
                {identity?.machine_id}
              </div>
            </div>

            <div>
              <div className="text-xs uppercase tracking-wide text-zinc-500">
                First Seen
              </div>

              <div className="mt-2 text-zinc-300">
                {identity?.first_seen
                  ? new Date(identity.first_seen).toLocaleString()
                  : "Unknown"}
              </div>
            </div>

            <div>
              <div className="text-xs uppercase tracking-wide text-zinc-500">
                Last Seen
              </div>

              <div className="mt-2 text-zinc-300">
                {identity?.last_seen
                  ? new Date(identity.last_seen).toLocaleString()
                  : "Unknown"}
              </div>
            </div>
          </div>
        </Card>

        {/* INVESTIGATION HISTORY */}
        <div>
          <h2 className="mb-4 text-xl font-semibold text-white">
            Investigation History
          </h2>

          {incidentSummary?.forensic_summary && (
            <div className="mb-6">
              <h3 className="mb-3 text-lg font-medium text-red-400">
                Pre-Quarantine Forensic Evidence
              </h3>
              <ForensicPanel summary={incidentSummary} />
            </div>
          )}

          <div className="grid gap-6 xl:grid-cols-2">
            <RiskTrend data={history ?? []} />
            <RulesCard rules={rules} />
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-2">
            <ReasonsCard reasons={reasons} />
          </div>

          <div className="mt-6">
            <NodeTimeline events={history ?? []} />
          </div>
        </div>
      </div>
    </div>
  );
}
