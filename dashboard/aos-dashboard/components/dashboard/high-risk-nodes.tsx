"use client";

import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

import { useNodes } from "@/hooks/useDashboard";

export function HighRiskNodes() {
  const { data } = useNodes();

  const nodes = [...(data ?? [])]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10);

  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-4 text-lg font-semibold text-white">High Risk Nodes</h2>

      <div className="space-y-3">
        {nodes.length > 0 ? (
          nodes.map((node) => (
            <div
              key={node.node}
              className="
              flex
              items-center
              justify-between
              rounded-lg
              border
              border-zinc-800
              bg-zinc-950
              p-3
            "
            >
              <div>
                <div className="font-medium text-white">{node.node}</div>

                <div className="text-xs text-zinc-500">{node.trust_status}</div>
              </div>

              <div className="flex items-center gap-3">
                <Badge>{node.status}</Badge>

                <span className="font-bold text-red-400">
                  {node.risk_score.toFixed(1)}
                </span>
              </div>
            </div>
          ))
        ) : (
          <div className="text-center text-sm text-zinc-300 h-full flex items-center justify-center p-4">
            No nodes are currently reporting high risk scores.
          </div>
        )}
      </div>
    </Card>
  );
}
