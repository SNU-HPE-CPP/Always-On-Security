"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
  CartesianGrid,
} from "recharts";

import { Card } from "@/components/ui/card";
import { useStats } from "@/hooks/useDashboard";

export function SeverityBreakdown() {
  const { data, isLoading } = useStats();

  const chartData = [
    {
      severity: "CRITICAL",
      count: data?.by_severity?.CRITICAL ?? 0,
    },
    {
      severity: "HIGH",
      count: data?.by_severity?.HIGH ?? 0,
    },
    {
      severity: "MEDIUM",
      count: data?.by_severity?.MEDIUM ?? 0,
    },
    {
      severity: "LOW",
      count: data?.by_severity?.LOW ?? 0,
    },
    {
      severity: "INFO",
      count: data?.by_severity?.INFO ?? 0,
    },
  ];

  if (isLoading) {
    return (
      <Card className="border-zinc-800 bg-zinc-900 p-6">
        <h2 className="mb-6 text-lg font-semibold text-white">
          Severity Breakdown
        </h2>

        <div className="flex h-[350px] items-center justify-center text-zinc-500">
          Loading...
        </div>
      </Card>
    );
  }

  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-6 text-lg font-semibold text-white">
        Severity Breakdown
      </h2>

      <div className="h-[350px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />

            <XAxis
              dataKey="severity"
              stroke="#71717a"
              tick={{ fill: "#a1a1aa" }}
            />

            <YAxis stroke="#71717a" tick={{ fill: "#a1a1aa" }} />

            <Tooltip
              contentStyle={{
                background: "#18181b",
                border: "1px solid #27272a",
                borderRadius: "12px",
                color: "#fff",
              }}
              labelStyle={{
                color: "#fff",
              }}
            />

            <Bar dataKey="count" fill="#3b82f6" radius={[8, 8, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
