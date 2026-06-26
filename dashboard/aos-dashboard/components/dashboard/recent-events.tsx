"use client";

import { formatDistanceToNow } from "date-fns";

import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";

import { useEvents } from "@/hooks/useDashboard";

const getBucketColor = (bucket: string) => {
  switch (bucket?.toLowerCase()) {
    case "info": return "bg-blue-900/50 text-blue-300 border border-blue-800";
    case "low": return "bg-green-900/50 text-green-300 border border-green-800";
    case "medium": return "bg-yellow-900/50 text-yellow-300 border border-yellow-800";
    case "high": return "bg-orange-900/50 text-orange-300 border border-orange-800";
    case "critical": return "bg-red-900/50 text-red-300 border border-red-800";
    default: return "bg-zinc-800 text-zinc-300 border border-zinc-700";
  }
};

export function RecentEvents() {
  const { data, isLoading } = useEvents();
  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6 xl:col-span-2">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Recent Telemetry Events</h2>

        <span className="text-sm text-zinc-500">Live Feed</span>
      </div>

      <ScrollArea className="h-[450px]">
        <div className="space-y-3">
          {isLoading && <div className="text-zinc-500">Loading...</div>}

          {data?.length === 0 && !isLoading && (
            <div className="text-zinc-500 text-sm">No events yet.</div>
          )}

          {data?.map((event: any) => (
            <div
              key={event.id}
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
                <span className="text-sm font-medium text-white">{event.event_type}</span>

                <span className="text-xs text-zinc-500">
                  {formatDistanceToNow(new Date(event.timestamp), {
                    addSuffix: true,
                  })}
                </span>
              </div>

              <div className="mt-3 grid grid-cols-4 gap-4 text-sm text-zinc-400">
                <div>
                  <span className="text-zinc-500 block text-xs">Node</span>
                  <span className="text-cyan-400">{event.node}</span>
                </div>
                <div>
                  <span className="text-zinc-500 block text-xs">CPU</span>
                  <span>{Number(event.cpu_usage || 0).toFixed(1)}%</span>
                </div>
                <div>
                  <span className="text-zinc-500 block text-xs">Memory</span>
                  <span>{Number(event.memory_usage || 0).toFixed(1)}%</span>
                </div>
                <div>
                  <span className="text-zinc-500 block text-xs">Risk Score</span>
                  <span>{Number(event.risk_score || 0).toFixed(2)}</span>
                </div>
              </div>

              <div className="mt-3 flex items-center gap-2">
                <span className="text-xs text-zinc-500">Bucket:</span>
                <span className={`text-xs px-2 py-1 rounded ${getBucketColor(event.bucket || 'info')}`}>
                  {(event.bucket || 'info').toUpperCase()}
                </span>
                {event.correlated && (
                  <span className="text-xs px-2 py-1 rounded bg-indigo-900/50 text-indigo-300">
                    CORRELATED
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </Card>
  );
}
