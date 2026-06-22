"use client";

import { Card } from "@/components/ui/card";

export function ReasonsCard({ reasons }: { reasons: string[] }) {
  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-4 text-xl font-semibold text-white">
        Detection Reasons
      </h2>

      <div className="space-y-2">
        {reasons.map((reason) => (
          <div
            key={reason}
            className="
              rounded-lg
              border
              border-zinc-800
              bg-zinc-950
              p-3
            "
          >
            {reason}
          </div>
        ))}
      </div>
    </Card>
  );
}
