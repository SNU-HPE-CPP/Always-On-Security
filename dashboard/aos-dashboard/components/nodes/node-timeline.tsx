"use client";

import { Card } from "@/components/ui/card";

export function NodeTimeline({ events }: { events: any[] }) {
  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        Incident Timeline
      </h2>

      <div className="space-y-4">
        {events.map((event, index) => (
          <div
            key={index}
            className="
              border-l-2
              border-cyan-500
              pl-4
            "
          >
            <div className="text-sm text-zinc-500">
              {new Date(event.timestamp).toLocaleString()}
            </div>

            <div className="mt-1 font-medium text-white">
              Risk Score: {event.risk_score}
            </div>

            <div className="text-sm text-zinc-400">Bucket: {event.bucket}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}
