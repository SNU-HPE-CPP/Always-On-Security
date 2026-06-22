"use client";

import CountUp from "react-countup";

import { ShieldAlert, AlertTriangle, Clock3, Shield } from "lucide-react";

import { Card } from "@/components/ui/card";
import { useStats } from "@/hooks/useDashboard";

export function StatCards() {
  const { data } = useStats();
  console.log(data)
  const critical =
    (data?.by_severity?.CRITICAL ?? 0) + (data?.by_severity?.HIGH ?? 0);

  const cards = [
    {
      title: "Total Alerts",
      value: data?.total ?? 0,
      icon: ShieldAlert,
      color: "text-red-500",
    },
    {
      title: "Critical / High",
      value: critical,
      icon: AlertTriangle,
      color: "text-orange-500",
    },
    {
      title: "Last 24 Hours",
      value: data?.recent_24h ?? 0,
      icon: Clock3,
      color: "text-purple-500",
    },
    {
      title: "Replay Attempts",
      value: data?.by_type.REPLAY_ATTACK ?? 0,
      icon: Shield,
      color: "text-cyan-500",
    },
  ];

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => {
        const Icon = card.icon;

        return (
          <Card
            key={card.title}
            className="
              bg-zinc-900
              border-zinc-800
              hover:border-zinc-700
              transition-all
            "
          >
            <div className="p-6">
              <div className="flex justify-between">
                <div>
                  <p className="text-sm text-zinc-400">{card.title}</p>

                  <p className="mt-3 text-4xl font-bold">
                    <CountUp end={card.value} duration={1} />
                  </p>
                </div>

                <Icon className={`h-10 w-10 ${card.color}`} />
              </div>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
