"use client";

import Link from "next/link";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { Card } from "@/components/ui/card";

import { useNodes } from "@/hooks/useNodes";

import { StatusBadge } from "./status-badge";

export function NodesTable() {
  const { data, isLoading } = useNodes();
  if (isLoading) {
    return <Card className="p-6">Loading nodes...</Card>;
  }

  return (
    <Card className="border-zinc-800 bg-zinc-900 p-6">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Node</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Trust</TableHead>
            <TableHead>Risk</TableHead>
            <TableHead>Replay</TableHead>
            <TableHead>Flood</TableHead>
            <TableHead>Config</TableHead>
          </TableRow>
        </TableHeader>

        <TableBody>
          {data?.map((node: any) => (
            <TableRow
              key={node.node}
              className="
                hover:bg-zinc-800/50
                cursor-pointer
              "
            >
              <TableCell>
                <Link href={`/nodes/${node.node}`} className="text-cyan-400">
                  {node.node}
                </Link>
              </TableCell>

              <TableCell>
                <StatusBadge status={node.status} />
              </TableCell>

              <TableCell>{node.trust_status}</TableCell>

              <TableCell>
                <span
                  className={
                    node.risk_score > 80
                      ? "text-red-400 font-bold"
                      : node.risk_score > 50
                        ? "text-yellow-400 font-bold"
                        : "text-green-400 font-bold"
                  }
                >
                  {node.risk_score.toFixed(1)}
                </span>
              </TableCell>

              <TableCell>{node.replay_count}</TableCell>

              <TableCell>{node.flood_count}</TableCell>

              <TableCell>{node.config_tamper_count}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );
}
