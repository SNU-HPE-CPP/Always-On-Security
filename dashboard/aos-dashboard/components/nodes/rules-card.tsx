"use client";

import { Card } from "@/components/ui/card";

export function RulesCard({ rules }: { rules: string[] }) {
  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-4 text-xl font-semibold">Matched Rules</h2>

      <div className="space-y-2">
        {rules.map((rule) => (
          <div
            key={rule}
            className="
              rounded-lg
              bg-zinc-950
              p-3
              text-sm
            "
          >
            {rule}
          </div>
        ))}
      </div>
    </Card>
  );
}
