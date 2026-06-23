"use client";

import { ScenarioLauncher } from "@/components/playbook/scenario-launcher";
import { BookOpen, Swords, AlertTriangle } from "lucide-react";

export default function PlaybookPage() {
  return (
    <div className="relative min-h-screen bg-zinc-950">
      {/* Background glow */}
      <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
        <div className="absolute left-0 top-0 h-96 w-96 rounded-full bg-red-500/5 blur-3xl" />
        <div className="absolute right-0 top-0 h-96 w-96 rounded-full bg-orange-500/5 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-96 w-96 rounded-full bg-purple-500/5 blur-3xl" />
      </div>

      <div className="mx-auto max-w-7xl p-8 space-y-8">
        {/* ── Page header ── */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/15 ring-2 ring-red-500/40">
              <BookOpen className="h-6 w-6 text-red-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-white">
                Live Attack Playbook
              </h1>
              <p className="text-sm text-zinc-400 mt-0.5">
                Execute scripted multi-step attack scenarios with real-time narrated detection timelines
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            <span className="text-xs font-medium text-amber-300">Demo Environment Only</span>
          </div>
        </div>

        {/* ── How it works ── */}
        <div className="grid grid-cols-3 gap-4">
          {[
            {
              step: "1",
              icon: Swords,
              title: "Select a Scenario",
              desc: "Choose from pre-scripted APT, supply chain, and coordinated intrusion attack chains.",
              color: "text-red-400",
              bg: "bg-red-500/10 ring-red-500/30",
            },
            {
              step: "2",
              icon: BookOpen,
              title: "Watch Narrated Timeline",
              desc: "Each step fires in sequence with live status updates and annotations explaining what the system detects and why.",
              color: "text-amber-400",
              bg: "bg-amber-500/10 ring-amber-500/30",
            },
            {
              step: "3",
              icon: AlertTriangle,
              title: "Review Enforcement Response",
              desc: "The risk engine processes the signals and escalates to the Human Review Queue or quarantine automatically.",
              color: "text-cyan-400",
              bg: "bg-cyan-500/10 ring-cyan-500/30",
            },
          ].map(({ step, icon: Icon, title, desc, color, bg }) => (
            <div key={step} className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
              <div className={`mb-3 flex h-8 w-8 items-center justify-center rounded-lg ring-1 ${bg}`}>
                <Icon className={`h-4 w-4 ${color}`} />
              </div>
              <div className="text-[10px] font-mono text-zinc-600 mb-1">STEP {step}</div>
              <h3 className="text-sm font-bold text-white mb-1">{title}</h3>
              <p className="text-xs text-zinc-500 leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>

        {/* ── Divider ── */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-zinc-800" />
          </div>
          <div className="relative flex justify-center">
            <span className="bg-zinc-950 px-4 text-xs font-medium uppercase tracking-widest text-zinc-600">
              Scenario Library
            </span>
          </div>
        </div>

        {/* ── Scenario launcher ── */}
        <ScenarioLauncher />
      </div>
    </div>
  );
}
