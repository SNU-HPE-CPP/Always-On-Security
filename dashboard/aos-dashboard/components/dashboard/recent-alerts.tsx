"use client";

import { formatDistanceToNow } from "date-fns";

import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";

import { useAlerts } from "@/hooks/useDashboard";

import { SeverityBadge } from "./severity-badge";

export function RecentAlerts() {
  const { data, isLoading } = useAlerts();
  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>

        <span className="text-sm text-zinc-500">Last 10 alerts</span>
      </div>

      <ScrollArea className="h-[450px]">
        <div className="space-y-3">
          {isLoading && <div className="text-zinc-500">Loading...</div>}

          {data?.map((alert: any) => (
            <div
              key={alert.alert_id}
              className="
                rounded-xl
                border
                border-zinc-800
                bg-zinc-950
                p-4
                transition-all
                hover:border-zinc-700
              "
            >
              <div className="flex items-center justify-between">
                <SeverityBadge severity={alert.severity} />

                <span className="text-xs text-zinc-500">
                  {formatDistanceToNow(new Date(alert.timestamp), {
                    addSuffix: true,
                  })}
                </span>
              </div>

              <div className="mt-3">
                <h3 className="font-medium text-white">{alert.threat_type}</h3>

                <p className="mt-1 text-sm text-zinc-400">
                  {alert.description}
                </p>
              </div>

              <div className="mt-3 flex items-center gap-2">
                <span className="text-xs text-zinc-500">Node:</span>

                <span className="text-xs text-cyan-400">{alert.node_id}</span>
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </Card>
  );
}
