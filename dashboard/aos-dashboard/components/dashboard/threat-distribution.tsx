"use client";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import { Card } from "@/components/ui/card";
import { useStats } from "@/hooks/useDashboard";

const COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
  "#3b82f6",
  "#8b5cf6",
  "#06b6d4",
];

export function ThreatDistribution() {
  const { data, isLoading } = useStats();

  const chartData = Object.entries((data?.by_type ?? {}) as Record<string, number>)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7)
    .map(([name, value]) => ({
      name: name.replaceAll("_", " "),
      value,
    }));

  if (isLoading) {
    return (
      <Card className="border-zinc-800 bg-zinc-900 p-6">
        <h2 className="mb-6 text-lg font-semibold text-white">
          Threat Distribution
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
        Threat Distribution
      </h2>

      <div className="h-[350px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              outerRadius={120}
              innerRadius={60}
              paddingAngle={2}
            >
              {chartData.map((_, index) => (
                <Cell key={index} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>

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

            <Legend
              wrapperStyle={{
                color: "#a1a1aa",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
