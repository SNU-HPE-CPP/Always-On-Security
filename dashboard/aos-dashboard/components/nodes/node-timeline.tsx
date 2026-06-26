"use client";

import { Card } from "@/components/ui/card";

export function NodeTimeline({ events }: { events: any[] }) {
  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        Incident Timeline
      </h2>

      <div className="space-y-4">
        {events.map((event, index) => {
          const isRemediation = event.bucket === "auto" && event.matched_rules?.includes("AUTO_REMEDIATION");
          
          return (
            <div
              key={index}
              className={`border-l-2 pl-4 ${isRemediation ? "border-amber-500 bg-amber-500/5 p-3 rounded-r-lg" : "border-cyan-500"}`}
            >
              <div className="flex items-center justify-between">
                <div className="text-sm text-zinc-500">
                  {new Date(event.timestamp).toLocaleString()}
                </div>
                {isRemediation && (
                  <span className="text-xs font-bold text-amber-500 bg-amber-500/20 px-2 py-1 rounded">AUTO REMEDIATION</span>
                )}
              </div>

              {!isRemediation && (
                <div className="mt-1 font-medium text-white">
                  Risk Score: {event.risk_score} <span className="text-sm font-normal text-zinc-500">({event.bucket})</span>
                </div>
              )}

              {event.reasons && event.reasons.length > 0 && (
                <div className="mt-2 text-sm text-zinc-300">
                  {event.reasons.map((r: string, i: number) => (
                    <div key={i}>• {r}</div>
                  ))}
                </div>
              )}

              {isRemediation && event.evidence && event.evidence.output && (
                <div className="mt-2 bg-black/50 p-2 rounded text-xs font-mono text-zinc-400 whitespace-pre-wrap">
                  {event.evidence.output}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}
