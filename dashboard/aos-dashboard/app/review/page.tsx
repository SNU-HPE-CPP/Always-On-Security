"use client";

import { useReviewQueue } from "@/hooks/useReviewQueue";
import { IncidentCard } from "@/components/review/incident-card";
import { ShieldAlert, CheckCircle2, RefreshCw, Clock } from "lucide-react";

export default function ReviewPage() {
  const { data: queue, isLoading, refetch, isFetching } = useReviewQueue();

  const pending = queue ?? [];

  return (
    <div className="relative min-h-screen bg-zinc-950">
      {/* Background glow */}
      <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
        <div className="absolute left-0 top-0 h-96 w-96 rounded-full bg-amber-500/5 blur-3xl" />
        <div className="absolute right-0 bottom-0 h-96 w-96 rounded-full bg-red-500/5 blur-3xl" />
      </div>

      <div className="mx-auto max-w-5xl p-8 space-y-8">
        {/* ── Page header ── */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/15 ring-2 ring-amber-500/40">
              <ShieldAlert className="h-6 w-6 text-amber-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-white">
                Human Review Queue
              </h1>
              <p className="text-sm text-zinc-400 mt-0.5">
                Nodes flagged by the risk engine for admin approval before resuming operations
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {pending.length > 0 && (
              <div className="flex items-center gap-2 rounded-full border border-amber-500/40 bg-amber-500/15 px-4 py-1.5">
                <div className="h-2 w-2 animate-pulse rounded-full bg-amber-500" />
                <span className="text-sm font-bold text-amber-300">
                  {pending.length} Pending
                </span>
              </div>
            )}
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* ── Content ── */}
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-zinc-500 gap-3">
            <RefreshCw className="h-5 w-5 animate-spin" />
            <span>Loading review queue…</span>
          </div>
        ) : pending.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-2xl border border-zinc-800 bg-zinc-900/40 py-20 text-center">
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-green-500/10 ring-2 ring-green-500/20">
              <CheckCircle2 className="h-8 w-8 text-green-400" />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Queue is Clear</h2>
            <p className="text-sm text-zinc-500 max-w-sm">
              No nodes are currently awaiting review. All systems are operating normally.
            </p>
            <div className="mt-6 flex items-center gap-2 text-xs text-zinc-600">
              <Clock className="h-3.5 w-3.5" />
              Auto-refreshing every 5 seconds
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            <div className="flex items-center gap-2 text-xs text-zinc-600">
              <Clock className="h-3.5 w-3.5" />
              Auto-refreshing every 5 seconds · {pending.length} node{pending.length !== 1 ? "s" : ""} awaiting review
            </div>
            {pending.map((item) => (
              <IncidentCard key={item.node} node={item.node} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
