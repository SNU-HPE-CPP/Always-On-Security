"use client";

import { useState } from "react";
import { IncidentSummary } from "@/types/review";
import { useIncidentSummary } from "@/hooks/useIncidentSummary";
import { useApproveNode } from "@/hooks/useApproveNode";
import { useDenyNode } from "@/hooks/useDenyNode";
import { NarrativeBlock } from "./narrative-block";
import { ThreatTimeline } from "./threat-timeline";
import {
  Server,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  Clock,
  Cpu,
  Network,
  FileText,
  Loader2,
  ShieldOff,
  HardDrive,
} from "lucide-react";
import { toast } from "sonner";

export function ForensicPanel({ summary }: { summary: IncidentSummary }) {
  const f = summary.forensic_summary;
  if (!f) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 px-4 py-6 text-center text-sm text-zinc-500">
        No forensic snapshot captured yet.
      </div>
    );
  }
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
      {[
        { icon: Cpu,      label: "Processes",    value: f.process_count,       sub: "running at capture" },
        { icon: Network,  label: "Connections",  value: f.network_connections, sub: "active TCP sockets" },
        { icon: HardDrive,label: "Container Image", value: f.container_image?.split("/").pop()?.slice(0, 20) ?? "—", sub: "image tag" },
        { icon: FileText, label: "Trigger",      value: f.trigger,             sub: "capture reason" },
        { icon: Clock,    label: "Captured At",  value: f.captured_at ? new Date(f.captured_at).toLocaleTimeString() : "—", sub: "UTC time" },
        { icon: ShieldOff,label: "Artifact",     value: f.artifact_path ? "Saved" : "None", sub: "JSON file" },
      ].map(({ icon: Icon, label, value, sub }) => (
        <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3">
          <div className="flex items-center gap-2 mb-1">
            <Icon className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</span>
          </div>
          <div className="text-base font-bold text-white">{value}</div>
          <div className="text-[10px] text-zinc-600">{sub}</div>
        </div>
      ))}
    </div>
  );
}

function SectionToggle({
  label,
  children,
  defaultOpen = false,
}: {
  label: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl border border-zinc-800 overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 bg-zinc-900/80 hover:bg-zinc-800/60 transition-colors"
      >
        <span className="text-sm font-semibold text-zinc-200">{label}</span>
        {open ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
      </button>
      {open && <div className="p-4">{children}</div>}
    </div>
  );
}

export function IncidentCard({ node }: { node: string }) {
  const { data: summary, isLoading, isError } = useIncidentSummary(node);
  const approveNode = useApproveNode();
  const denyNode    = useDenyNode();
  const [notes, setNotes]       = useState("");
  const [expanded, setExpanded] = useState(true);

  const handleApprove = async () => {
    if (!confirm(`Approve node ${node} and resume operations?`)) return;
    try {
      await approveNode.mutateAsync(node);
      toast.success(`Node ${node} approved`, { description: "Node is resuming operations." });
    } catch {
      toast.error("Approval failed");
    }
  };

  const handleDeny = async () => {
    if (!confirm(`Deny and quarantine ${node}? This will stop the container and capture forensics.`)) return;
    try {
      await denyNode.mutateAsync({ node, notes });
      toast.success(`Node ${node} quarantined`, { description: "Forensic snapshot captured and container stopped." });
    } catch {
      toast.error("Deny action failed");
    }
  };

  const riskScore = summary?.risk_score ?? 0;
  const riskColor =
    riskScore > 100 ? "text-red-400" :
    riskScore > 70  ? "text-orange-400" :
                      "text-yellow-400";

  return (
    <div className="rounded-2xl border border-amber-500/30 bg-zinc-950 shadow-xl shadow-amber-900/10 overflow-hidden">
      {/* Card Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 bg-amber-500/5 px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/15 ring-1 ring-amber-500/40">
            <Server className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white font-mono">{node}</h3>
            <p className="text-xs text-amber-400/80">Awaiting Human Review</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className={`text-2xl font-black tabular-nums ${riskColor}`}>
              {riskScore.toFixed(1)}
            </div>
            <div className="text-[10px] uppercase tracking-wide text-zinc-500">Risk Score</div>
          </div>
          <button
            onClick={() => setExpanded((e) => !e)}
            className="rounded-lg border border-zinc-700 bg-zinc-900 p-2 hover:bg-zinc-800 transition-colors"
          >
            {expanded
              ? <ChevronUp className="h-4 w-4 text-zinc-400" />
              : <ChevronDown className="h-4 w-4 text-zinc-400" />
            }
          </button>
        </div>
      </div>

      {expanded && (
        <div className="p-6 space-y-5">
          {/* Loading / Error states */}
          {isLoading && (
            <div className="flex items-center justify-center gap-2 py-10 text-zinc-500">
              <Loader2 className="h-5 w-5 animate-spin" />
              <span className="text-sm">Generating incident analysis…</span>
            </div>
          )}
          {isError && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              Failed to load incident analysis. The node may not have enough data yet.
            </div>
          )}

          {summary && (
            <>
              {/* AI Narrative */}
              <NarrativeBlock summary={summary} />

              {/* Threat Timeline */}
              <SectionToggle label={`Threat Timeline (${summary.timeline.length} events)`} defaultOpen={true}>
                <ThreatTimeline entries={summary.timeline} />
              </SectionToggle>

              {/* Forensic Evidence */}
              <SectionToggle label="Pre-Quarantine Forensic Evidence">
                <ForensicPanel summary={summary} />
              </SectionToggle>

              {/* Top Threats table */}
              {summary.top_threats.length > 0 && (
                <SectionToggle label="Detected Threat Types">
                  <div className="space-y-2">
                    {summary.top_threats.map((t) => (
                      <div key={t.threat_type} className="flex items-center justify-between rounded-lg border border-zinc-800 px-3 py-2">
                        <span className="font-mono text-xs text-zinc-200">{t.threat_type}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-zinc-500">×{t.count}</span>
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ring-1 ${
                            t.severity === "CRITICAL" ? "bg-red-500/20 text-red-300 ring-red-500/30" :
                            t.severity === "HIGH"     ? "bg-orange-500/20 text-orange-300 ring-orange-500/30" :
                                                        "bg-yellow-500/20 text-yellow-300 ring-yellow-500/30"
                          }`}>{t.severity}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </SectionToggle>
              )}
            </>
          )}

          {/* Admin action bar */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Admin Decision</h4>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Add review notes (optional)…"
              rows={2}
              maxLength={500}
              className="w-full resize-none rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500"
            />
            <div className="flex gap-3">
              <button
                onClick={handleApprove}
                disabled={approveNode.isPending || denyNode.isPending}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-green-500/40 bg-green-500/15 px-4 py-2.5 text-sm font-semibold text-green-300 transition-all hover:bg-green-500/25 hover:border-green-500/60 disabled:opacity-50"
              >
                {approveNode.isPending
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <CheckCircle2 className="h-4 w-4" />
                }
                Approve & Resume
              </button>
              <button
                onClick={handleDeny}
                disabled={approveNode.isPending || denyNode.isPending}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-red-500/40 bg-red-500/15 px-4 py-2.5 text-sm font-semibold text-red-300 transition-all hover:bg-red-500/25 hover:border-red-500/60 disabled:opacity-50"
              >
                {denyNode.isPending
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <XCircle className="h-4 w-4" />
                }
                Deny & Quarantine
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
