"use client";

import { useState, useCallback, ComponentType } from "react";
import {
  Terminal,
  Network,
  RotateCcw,
  Package2,
  FileCode2,
  ShieldOff,
  Ghost,
  Repeat2,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  Swords,
  Loader2,
  FlaskConical,
} from "lucide-react";
import { toast } from "sonner";

import { useSimulateAttack } from "@/hooks/useSimulateAttack";
import { useNodes } from "@/hooks/useNodes";
import { AttackDefinition, AttackCategory, SimLog } from "@/types/simulate";

// ── Attack catalogue ──────────────────────────────────────────────────────────

const ATTACKS: AttackDefinition[] = [
  {
    id: "docker_exec",
    category: "exec",
    name: "Docker Exec Injection",
    description:
      "Runs a command inside the target container via Docker exec. Triggers the docker_collector event pipeline.",
    severity: "HIGH",
    expectedAlerts: ["CONTAINER_EXEC", "UNEXPECTED_EXEC"],
    nodeSpecific: true,
  },
  {
    id: "suspicious_restart",
    category: "exec",
    name: "Restart Storm",
    description:
      "Restarts the container 6× in rapid succession. The docker_collector fires SUSPICIOUS_RESTART_PATTERN after ≥5 restarts in 120 s.",
    severity: "MEDIUM",
    expectedAlerts: ["SUSPICIOUS_RESTART_PATTERN"],
    nodeSpecific: true,
  },
  {
    id: "runtime_drift_network",
    category: "network",
    name: "Network Drift Attack",
    description:
      "Attaches the container to an unexpected network segment (storage-net). Host-observer detects drift vs runtime_baseline.yaml. Auto-restores in 30 s.",
    severity: "HIGH",
    expectedAlerts: ["RUNTIME_DRIFT", "UNEXPECTED_NETWORK_ATTACH"],
    nodeSpecific: true,
  },
  {
    id: "image_mismatch",
    category: "exec",
    name: "Image Mismatch",
    description:
      "Simulates a running container whose image digest does not match the approved_images.yaml entry.",
    severity: "HIGH",
    expectedAlerts: ["IMAGE_MISMATCH"],
    nodeSpecific: true,
  },
  {
    id: "rogue_node",
    category: "protocol",
    name: "Rogue Node Injection",
    description:
      "Sends a HMAC-signed telemetry message to the Controller from an unknown node name. The allowlist check fails and a ROGUE_NODE alert is emitted.",
    severity: "CRITICAL",
    expectedAlerts: ["ROGUE_NODE"],
    nodeSpecific: false,
  },
  {
    id: "replay_attack",
    category: "protocol",
    name: "Replay Attack",
    description:
      "Re-transmits a previously seen msg_id to the Controller. The ReplayGuard rejects the duplicate and fires a REPLAY_ATTACK alert.",
    severity: "HIGH",
    expectedAlerts: ["REPLAY_ATTACK"],
    nodeSpecific: false,
  },
  {
    id: "config_tamper",
    category: "config",
    name: "Policy File Tamper",
    description:
      "Simulates rules.yaml being modified on disk. The host-observer hash check detects the mismatch and emits POLICY_TAMPER.",
    severity: "CRITICAL",
    expectedAlerts: ["POLICY_TAMPER"],
    nodeSpecific: false,
  },
  {
    id: "allowlist_tamper",
    category: "config",
    name: "Allowlist Tamper",
    description:
      "Simulates allowlist.yaml being modified. The host-observer raises ALLOWLIST_TAMPER — the highest severity config event.",
    severity: "CRITICAL",
    expectedAlerts: ["ALLOWLIST_TAMPER"],
    nodeSpecific: false,
  },
  {
    id: "multi_signal",
    category: "correlated",
    name: "Multi-Signal Chain",
    description:
      "Fires Docker exec then network drift on the same node within the 120 s correlation window. Triggers multi-signal scoring (2.5–3× multiplier).",
    severity: "CRITICAL",
    expectedAlerts: ["CONTAINER_EXEC", "RUNTIME_DRIFT", "↑ score multiplier"],
    nodeSpecific: true,
  },
];

// ── Category config ───────────────────────────────────────────────────────────

const CATEGORIES: { id: AttackCategory; label: string; color: string }[] = [
  { id: "all", label: "All Attacks", color: "text-zinc-300" },
  { id: "protocol", label: "Protocol", color: "text-violet-400" },
  { id: "exec", label: "Exec / Process", color: "text-orange-400" },
  { id: "network", label: "Network", color: "text-cyan-400" },
  { id: "config", label: "Config", color: "text-amber-400" },
  { id: "correlated", label: "Correlated", color: "text-red-400" },
];

const CATEGORY_STYLES: Record<string, string> = {
  protocol: "border-violet-500/40 bg-violet-500/5 hover:border-violet-400/60",
  exec: "border-orange-500/40 bg-orange-500/5 hover:border-orange-400/60",
  network: "border-cyan-500/40 bg-cyan-500/5 hover:border-cyan-400/60",
  config: "border-amber-500/40 bg-amber-500/5 hover:border-amber-400/60",
  correlated: "border-red-500/40 bg-red-500/5 hover:border-red-400/60",
};

const CATEGORY_CHIP: Record<string, string> = {
  protocol: "bg-violet-500/20 text-violet-300 ring-violet-500/30",
  exec: "bg-orange-500/20 text-orange-300 ring-orange-500/30",
  network: "bg-cyan-500/20 text-cyan-300 ring-cyan-500/30",
  config: "bg-amber-500/20 text-amber-300 ring-amber-500/30",
  correlated: "bg-red-500/20 text-red-300 ring-red-500/30",
};

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300 ring-1 ring-red-500/40",
  HIGH: "bg-orange-500/20 text-orange-300 ring-1 ring-orange-500/40",
  MEDIUM: "bg-yellow-500/20 text-yellow-300 ring-1 ring-yellow-500/40",
};

const ATTACK_ICONS: Record<string, ComponentType<{ className?: string }>> = {
  docker_exec: Terminal,
  suspicious_restart: RotateCcw,
  runtime_drift_network: Network,
  image_mismatch: Package2,
  rogue_node: Ghost,
  replay_attack: Repeat2,
  config_tamper: FileCode2,
  allowlist_tamper: ShieldOff,
  multi_signal: Zap,
};

const KNOWN_NODES = ["node1", "node2", "node3", "node4"];

// ── Sub-components ────────────────────────────────────────────────────────────

function AlertChip({ label }: { label: string }) {
  return (
    <span className="inline-block rounded px-1.5 py-0.5 text-[10px] font-mono font-medium bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700">
      {label}
    </span>
  );
}

function SimLogEntry({ entry }: { entry: SimLog }) {
  const timeStr = entry.firedAt.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div className="flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-sm transition-all">
      {entry.status === "pending" && (
        <Loader2 className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin text-zinc-400" />
      )}
      {entry.status === "success" && (
        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-green-400" />
      )}
      {entry.status === "error" && (
        <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] text-zinc-500">{timeStr}</span>
          <span className="font-medium text-zinc-200">{entry.attackName}</span>
          {entry.node && (
            <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-cyan-400">
              → {entry.node}
            </span>
          )}
        </div>
        <p className="mt-0.5 truncate text-xs text-zinc-500">{entry.message}</p>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AttackSimulator() {
  const [activeCategory, setActiveCategory] = useState<AttackCategory>("all");
  const [selectedNodes, setSelectedNodes] = useState<Record<string, string>>(
    () =>
      Object.fromEntries(
        KNOWN_NODES.map((_, i) => [ATTACKS[i]?.id ?? "", "node1"]),
      ),
  );
  const [firingIds, setFiringIds] = useState<Set<string>>(new Set());
  const [simLog, setSimLog] = useState<SimLog[]>([]);

  const { mutate } = useSimulateAttack();
  const { data: nodesData } = useNodes();

  // Build available node list from live data, fallback to known nodes
  const availableNodes: string[] =
    nodesData && nodesData.length > 0
      ? nodesData.map((n: { node: string }) => n.node)
      : KNOWN_NODES;

  const getNodeForAttack = useCallback(
    (attackId: string) =>
      selectedNodes[attackId] ?? availableNodes[0] ?? "node1",
    [selectedNodes, availableNodes],
  );

  const setNodeForAttack = (attackId: string, node: string) => {
    setSelectedNodes((prev) => ({ ...prev, [attackId]: node }));
  };

  const fireKey = (attackId: string, node?: string) =>
    `${attackId}:${node ?? "global"}`;

  const handleFire = (attack: AttackDefinition) => {
    const node = attack.nodeSpecific ? getNodeForAttack(attack.id) : undefined;
    const key = fireKey(attack.id, node);

    if (firingIds.has(key)) return;

    const logId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const logEntry: SimLog = {
      id: logId,
      attackId: attack.id,
      attackName: attack.name,
      node,
      firedAt: new Date(),
      status: "pending",
      message: "Firing…",
    };

    setSimLog((prev) => [logEntry, ...prev].slice(0, 8));
    setFiringIds((prev) => new Set(prev).add(key));

    mutate(
      { attack: attack.id, node },
      {
        onSuccess: (result) => {
          const msg =
            result.message ??
            (result.ok ? "Attack executed." : (result.error ?? "Failed."));
          setSimLog((prev) =>
            prev.map((e) =>
              e.id === logId
                ? {
                    ...e,
                    status: result.ok ? "success" : "error",
                    message: msg,
                  }
                : e,
            ),
          );
          if (result.ok) {
            toast.success(`${attack.name} executed`, { description: msg });
          } else {
            toast.error(`${attack.name} failed`, { description: msg });
          }
        },
        onError: (err: unknown) => {
          const msg = err instanceof Error ? err.message : "Network error.";
          setSimLog((prev) =>
            prev.map((e) =>
              e.id === logId ? { ...e, status: "error", message: msg } : e,
            ),
          );
          toast.error(`${attack.name} failed`, { description: msg });
        },
        onSettled: () => {
          setFiringIds((prev) => {
            const next = new Set(prev);
            next.delete(key);
            return next;
          });
        },
      },
    );
  };

  const filtered =
    activeCategory === "all"
      ? ATTACKS
      : ATTACKS.filter((a) => a.category === activeCategory);

  return (
    <section id="simulate" className="relative space-y-6 p-10">
      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/15 ring-1 ring-red-500/30">
            <FlaskConical className="h-5 w-5 text-red-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">
              Threat Simulation Lab
            </h2>
            <p className="text-sm text-zinc-500">
              Inject real attacks into the live detection pipeline
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5">
          <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
          <span className="text-xs font-medium text-amber-300">
            Demo Environment Only
          </span>
        </div>
      </div>

      {/* ── Category tabs ── */}
      <div className="flex flex-wrap gap-2">
        {CATEGORIES.map((cat) => {
          const isActive = activeCategory === cat.id;
          return (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              className={`
                rounded-lg border px-4 py-1.5 text-sm font-medium transition-all duration-200
                ${
                  isActive
                    ? `border-zinc-600 bg-zinc-800 ${cat.color}`
                    : "border-zinc-800 bg-zinc-900/50 text-zinc-500 hover:border-zinc-700 hover:text-zinc-300"
                }
              `}
            >
              {cat.label}
            </button>
          );
        })}
      </div>

      {/* ── Attack cards grid ── */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {filtered.map((attack) => {
          const Icon = ATTACK_ICONS[attack.id] ?? Swords;
          const node = attack.nodeSpecific
            ? getNodeForAttack(attack.id)
            : undefined;
          const key = fireKey(attack.id, node);
          const isFiring = firingIds.has(key);

          return (
            <div
              key={attack.id}
              className={`
                group relative flex flex-col rounded-xl border p-4 transition-all duration-300
                ${CATEGORY_STYLES[attack.category]}
              `}
            >
              {/* Category + Severity row */}
              <div className="mb-3 flex items-center justify-between">
                <span
                  className={`rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ${CATEGORY_CHIP[attack.category]}`}
                >
                  {attack.category}
                </span>
                <span
                  className={`rounded-md px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${SEVERITY_STYLES[attack.severity]}`}
                >
                  {attack.severity}
                </span>
              </div>

              {/* Icon + name */}
              <div className="mb-2 flex items-center gap-2.5">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-800 ring-1 ring-zinc-700">
                  <Icon className="h-4 w-4 text-zinc-300" />
                </div>
                <h3 className="font-semibold text-white leading-tight">
                  {attack.name}
                </h3>
              </div>

              {/* Description */}
              <p className="mb-3 text-xs leading-relaxed text-zinc-500 flex-1">
                {attack.description}
              </p>

              {/* Expected alerts */}
              <div className="mb-4 flex flex-wrap gap-1">
                {attack.expectedAlerts.map((a) => (
                  <AlertChip key={a} label={a} />
                ))}
              </div>

              {/* Node selector (node-specific attacks only) */}
              {attack.nodeSpecific && (
                <div className="mb-3">
                  <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-zinc-500">
                    Target Node
                  </label>
                  <div className="relative">
                    <select
                      value={getNodeForAttack(attack.id)}
                      onChange={(e) =>
                        setNodeForAttack(attack.id, e.target.value)
                      }
                      className="
                        w-full appearance-none rounded-lg border border-zinc-700 bg-zinc-900
                        px-3 py-1.5 pr-8 text-sm text-zinc-200
                        focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500
                        transition-colors
                      "
                    >
                      {availableNodes.map((n) => (
                        <option key={n} value={n}>
                          {n}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                  </div>
                </div>
              )}

              {/* Fire button */}
              <button
                onClick={() => handleFire(attack)}
                disabled={isFiring}
                className={`
                  group/btn relative flex w-full items-center justify-center gap-2
                  overflow-hidden rounded-lg px-4 py-2 text-sm font-semibold
                  transition-all duration-200 active:scale-[0.98]
                  ${
                    isFiring
                      ? "cursor-not-allowed bg-zinc-800 text-zinc-500"
                      : attack.severity === "CRITICAL"
                        ? "bg-red-600/80 text-white hover:bg-red-600 hover:shadow-lg hover:shadow-red-900/30"
                        : attack.severity === "HIGH"
                          ? "bg-orange-600/80 text-white hover:bg-orange-600 hover:shadow-lg hover:shadow-orange-900/30"
                          : "bg-yellow-600/80 text-white hover:bg-yellow-600 hover:shadow-lg hover:shadow-yellow-900/30"
                  }
                `}
              >
                {isFiring ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Executing…
                  </>
                ) : (
                  <>
                    <Swords className="h-4 w-4" />
                    Execute Attack
                  </>
                )}
                {/* Shimmer effect on hover */}
                {!isFiring && (
                  <span className="pointer-events-none absolute inset-0 -translate-x-full skew-x-12 bg-white/10 transition-transform duration-500 group-hover/btn:translate-x-full" />
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* ── Simulation log ── */}
      {simLog.length > 0 && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-4">
          <div className="mb-3 flex items-center gap-2">
            <Clock className="h-4 w-4 text-zinc-500" />
            <h3 className="text-sm font-semibold text-zinc-300">
              Simulation Log
            </h3>
            <span className="ml-auto rounded-full bg-zinc-800 px-2 py-0.5 text-[11px] text-zinc-500">
              last {simLog.length}
            </span>
          </div>
          <div className="space-y-2">
            {simLog.map((entry) => (
              <SimLogEntry key={entry.id} entry={entry} />
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
