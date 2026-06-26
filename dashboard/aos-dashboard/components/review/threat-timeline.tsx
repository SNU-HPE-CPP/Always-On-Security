"use client";

import { TimelineEntry } from "@/types/review";
import {
  AlertTriangle,
  ShieldAlert,
  Activity,
  GitBranch,
  Clock,
} from "lucide-react";

const SEVERITY_CONFIG: Record<string, { dot: string; border: string; label: string }> = {
  CRITICAL: { dot: "bg-red-500 shadow-red-500/50 shadow-md", border: "border-red-500/30", label: "text-red-400" },
  HIGH:     { dot: "bg-orange-500 shadow-orange-500/50 shadow-md", border: "border-orange-500/30", label: "text-orange-400" },
  MEDIUM:   { dot: "bg-yellow-500", border: "border-yellow-500/30", label: "text-yellow-400" },
  LOW:      { dot: "bg-blue-500",   border: "border-blue-500/30",   label: "text-blue-400" },
  INFO:     { dot: "bg-zinc-500",   border: "border-zinc-700",      label: "text-zinc-400" },
};

const SOURCE_ICON: Record<string, React.ElementType> = {
  security_alert: ShieldAlert,
  risk_event: Activity,
};

function TimelineIcon({ entry }: { entry: TimelineEntry }) {
  const Icon = SOURCE_ICON[entry.source] ?? AlertTriangle;
  const cfg  = SEVERITY_CONFIG[entry.severity] ?? SEVERITY_CONFIG.INFO;
  return (
    <div className={`relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border ${cfg.border} bg-zinc-900`}>
      <Icon className={`h-3.5 w-3.5 ${cfg.label}`} />
    </div>
  );
}

export function ThreatTimeline({ entries }: { entries: TimelineEntry[] }) {
  if (!entries || entries.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 px-4 py-8 text-center text-sm text-zinc-500">
        No timeline events yet.
      </div>
    );
  }

  return (
    <div className="relative">
      {/* Vertical line */}
      <div className="absolute left-4 top-0 bottom-0 w-px bg-zinc-800" />

      <div className="space-y-3 pl-14">
        {entries.map((entry, i) => {
          const cfg = SEVERITY_CONFIG[entry.severity] ?? SEVERITY_CONFIG.INFO;
          return (
            <div key={i} className="relative">
              {/* Dot on the line */}
              <div className={`absolute -left-10 top-1 h-3 w-3 rounded-full border-2 border-zinc-900 ${cfg.dot}`} />

              <div className={`rounded-lg border ${cfg.border} bg-zinc-900/60 px-3 py-2 transition-all hover:bg-zinc-900`}>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-bold uppercase tracking-wide ${cfg.label}`}>
                    {entry.severity}
                  </span>
                  <span className="font-mono text-[11px] font-medium text-zinc-200">
                    {entry.event_type}
                  </span>
                  {entry.correlated && (
                    <span className="ml-auto flex items-center gap-1 rounded bg-purple-500/20 px-1.5 py-0.5 text-[9px] font-bold uppercase text-purple-300 ring-1 ring-purple-500/30">
                      <GitBranch className="h-2.5 w-2.5" /> Correlated
                    </span>
                  )}
                  {entry.mitre_id && (
                    <span className="ml-auto rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[9px] text-zinc-400 ring-1 ring-zinc-700">
                      {entry.mitre_id}
                    </span>
                  )}
                </div>
                <p className="text-xs text-zinc-400 leading-relaxed">{entry.description}</p>
                <div className="mt-1 flex items-center gap-1 text-[10px] text-zinc-600">
                  <Clock className="h-2.5 w-2.5" />
                  {entry.display_time} · {entry.ago}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
