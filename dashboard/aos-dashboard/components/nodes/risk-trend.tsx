"use client";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

import { Card } from "@/components/ui/card";

export function RiskTrend({ data }: { data: any[] }) {
  const chartData = [...data].reverse().map((event) => ({
    time: new Date(event.timestamp).toLocaleTimeString(),
    risk: event.risk_score,
  }));

  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">Risk Trend</h2>

      <div className="h-[300px]">
        <ResponsiveContainer>
          <LineChart data={chartData}>
            <CartesianGrid stroke="#27272a" />

            <XAxis dataKey="time" stroke="#71717a" />

            <YAxis stroke="#71717a" />

            <Tooltip
              contentStyle={{
                background: "#18181b",
                border: "1px solid #27272a",
              }}
            />

            <Line
              type="monotone"
              dataKey="risk"
              stroke="#ef4444"
              strokeWidth={3}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
