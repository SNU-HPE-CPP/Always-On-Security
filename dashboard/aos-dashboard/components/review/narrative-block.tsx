"use client";

import { IncidentSummary } from "@/types/review";
import { Sparkles, AlertTriangle, CheckCircle2, Search } from "lucide-react";

const ACTION_CONFIG = {
  QUARANTINE: {
    color: "text-red-300",
    bg: "bg-red-500/10 border-red-500/30",
    icon: AlertTriangle,
    label: "Recommendation: Quarantine",
  },
  INVESTIGATE_FURTHER: {
    color: "text-amber-300",
    bg: "bg-amber-500/10 border-amber-500/30",
    icon: Search,
    label: "Recommendation: Investigate Further",
  },
  APPROVE_AND_RESUME: {
    color: "text-green-300",
    bg: "bg-green-500/10 border-green-500/30",
    icon: CheckCircle2,
    label: "Recommendation: Approve & Resume",
  },
};

const CONFIDENCE_CONFIG = {
  HIGH:   { color: "text-red-400",   bg: "bg-red-500/10 ring-red-500/30" },
  MEDIUM: { color: "text-amber-400", bg: "bg-amber-500/10 ring-amber-500/30" },
  LOW:    { color: "text-zinc-400",  bg: "bg-zinc-700/40 ring-zinc-600/30" },
};

/** Renders **bold** and `code` markdown in narrative strings */
function NarrativeText({ text }: { text: string }) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <p className="text-sm leading-relaxed text-zinc-300">
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**")) {
          return <strong key={i} className="text-white font-semibold">{part.slice(2, -2)}</strong>;
        }
        if (part.startsWith("`") && part.endsWith("`")) {
          return (
            <code key={i} className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300 ring-1 ring-zinc-700">
              {part.slice(1, -1)}
            </code>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </p>
  );
}

export function NarrativeBlock({ summary }: { summary: IncidentSummary }) {
  const actionCfg     = ACTION_CONFIG[summary.recommended_action] ?? ACTION_CONFIG.INVESTIGATE_FURTHER;
  const confidenceCfg = CONFIDENCE_CONFIG[summary.confidence_level] ?? CONFIDENCE_CONFIG.LOW;
  const ActionIcon    = actionCfg.icon;

  return (
    <div className="space-y-4">
      {/* AI badge + confidence */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-1.5">
          <Sparkles className="h-3.5 w-3.5 text-violet-400" />
          <span className="text-xs font-semibold text-violet-300">Incident Analysis</span>
        </div>
        <span className={`rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide ring-1 ${confidenceCfg.bg} ${confidenceCfg.color}`}>
          {summary.confidence_level} Confidence
        </span>
      </div>

      {/* Narrative text */}
      <div className="rounded-lg border border-zinc-700/50 bg-zinc-900/60 p-4">
        <NarrativeText text={summary.narrative} />
      </div>

      {/* Recommendation banner */}
      <div className={`flex items-center gap-3 rounded-lg border px-4 py-3 ${actionCfg.bg}`}>
        <ActionIcon className={`h-4 w-4 shrink-0 ${actionCfg.color}`} />
        <span className={`text-sm font-semibold ${actionCfg.color}`}>{actionCfg.label}</span>
      </div>

      {/* Quick stats row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Risk Score", value: summary.risk_score.toFixed(1), sub: "cumulative" },
          { label: "Total Alerts", value: summary.total_alerts, sub: "security events" },
          { label: "Correlations", value: summary.correlations.length, sub: "rules matched" },
        ].map(({ label, value, sub }) => (
          <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3 text-center">
            <div className="text-xl font-bold text-white">{value}</div>
            <div className="text-[11px] font-medium text-zinc-300">{label}</div>
            <div className="text-[10px] text-zinc-600">{sub}</div>
          </div>
        ))}
      </div>

      {/* Correlation findings */}
      {summary.correlations.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
            Multi-Signal Correlations
          </h4>
          {summary.correlations.map((c, i) => (
            <div key={i} className="flex items-center gap-3 rounded-lg border border-purple-500/20 bg-purple-500/5 px-3 py-2">
              <span className="rounded bg-purple-500/20 px-2 py-0.5 font-mono text-xs font-bold text-purple-300 ring-1 ring-purple-500/30">
                {c.multiplier}×
              </span>
              <div>
                <div className="text-xs font-semibold text-purple-200">{c.label}</div>
                <div className="text-[11px] text-zinc-500">{c.matched_types.join(" + ")}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* NIST + MITRE badges */}
      {(summary.nist_references.length > 0 || summary.mitre_techniques.length > 0) && (
        <div className="space-y-2">
          {summary.nist_references.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-zinc-600 self-center">NIST</span>
              {summary.nist_references.map((ref) => (
                <span key={ref} className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] text-cyan-400 ring-1 ring-cyan-500/20">
                  {ref}
                </span>
              ))}
            </div>
          )}
          {summary.mitre_techniques.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-zinc-600 self-center">MITRE</span>
              {summary.mitre_techniques.slice(0, 4).map((t) => (
                <span key={t.id} title={t.name} className="rounded bg-orange-500/10 px-2 py-0.5 font-mono text-[10px] text-orange-400 ring-1 ring-orange-500/20 cursor-help">
                  {t.id}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
