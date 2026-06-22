"use client";

import { useState } from "react";
import { useDebounce } from "use-debounce";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { useAlerts } from "@/hooks/useAlerts";

import { AlertDialog } from "./alert-dialog";
import { SeverityBadge } from "@/components/dashboard/severity-badge";

export function AlertsTable() {
  const [severity, setSeverity] = useState<string | undefined>();

  const [nodeId, setNodeId] = useState("");
  const [threatType, setThreatType] = useState("");

  const [debouncedNodeId] = useDebounce(nodeId, 500);
  const [debouncedThreatType] = useDebounce(threatType, 500);

  const { data, isLoading } = useAlerts({
    severity,
    node_id: debouncedNodeId || undefined,
    threat_type: debouncedThreatType || undefined,
  });

  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  const [open, setOpen] = useState(false);

  return (
    <>
      <Card className="border-zinc-800 bg-zinc-900 p-6">
        <div className="mb-6 flex flex-wrap gap-4">
          <Input
            placeholder="Filter by node..."
            value={nodeId}
            onChange={(e) => setNodeId(e.target.value)}
            className="w-64 border-zinc-700 bg-zinc-950"
          />

          <Input
            placeholder="Filter by threat type..."
            value={threatType}
            onChange={(e) => setThreatType(e.target.value)}
            className="w-64 border-zinc-700 bg-zinc-950"
          />

          <Select
            value={severity ?? "ALL"}
            onValueChange={(value) =>
              setSeverity(value === "ALL" ? undefined : value)
            }
          >
            <SelectTrigger className="w-48 border-zinc-700 bg-zinc-950">
              <SelectValue />
            </SelectTrigger>

            <SelectContent>
              <SelectItem value="ALL">All Severities</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
              <SelectItem value="HIGH">High</SelectItem>
              <SelectItem value="MEDIUM">Medium</SelectItem>
              <SelectItem value="LOW">Low</SelectItem>
              <SelectItem value="INFO">Info</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="rounded-md border border-zinc-800">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Threat Type</TableHead>
                <TableHead>Node</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Timestamp</TableHead>
              </TableRow>
            </TableHeader>

            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="h-24 text-center text-zinc-400"
                  >
                    Loading alerts...
                  </TableCell>
                </TableRow>
              ) : data?.length ? (
                data.map((alert: any) => (
                  <TableRow
                    key={alert.alert_id}
                    className="
                      cursor-pointer
                      transition-colors
                      hover:bg-zinc-800/50
                    "
                    onClick={() => {
                      setSelectedAlert(alert);
                      setOpen(true);
                    }}
                  >
                    <TableCell>
                      <SeverityBadge severity={alert.severity} />
                    </TableCell>

                    <TableCell className="font-medium">
                      {alert.threat_type}
                    </TableCell>

                    <TableCell className="text-cyan-400">
                      {alert.node_id}
                    </TableCell>

                    <TableCell className="max-w-[500px] truncate">
                      {alert.description}
                    </TableCell>

                    <TableCell>
                      {new Date(alert.timestamp).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="h-24 text-center text-zinc-400"
                  >
                    No alerts found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </Card>

      <AlertDialog open={open} onOpenChange={setOpen} alert={selectedAlert} />
    </>
  );
}
