"use client";

import { useState, useEffect, useRef } from "react";
import { useSimulateAttack } from "@/hooks/useSimulateAttack";
import { useNodes } from "@/hooks/useNodes";
import {
  CheckCircle2,
  Clock,
  Loader2,
  AlertTriangle,
  ShieldAlert,
  Activity,
  Target,
  ChevronDown,
} from "lucide-react";

// ── Scenario definitions ─────────────────────────────────────────────────────

export interface PlaybookStep {
  id: string;
  name: string;
  attack: string;
  nodeSpecific: boolean;
  description: string;
  expectedAlert: string;
  waitMs: number;    // ms to wait before firing (narrative delay)
  annotation: string; // what the system should detect / why this matters
}

export interface PlaybookScenario {
  id: string;
  name: string;
  description: string;
  difficulty: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  estimatedMinutes: number;
  targetBucket: "human" | "quarantine";
  steps: PlaybookStep[];
  icon: React.ElementType;
}

const SCENARIOS: PlaybookScenario[] = [
  {
    id: "apt_lateral_movement",
    name: "APT Lateral Movement",
    description:
      "Simulates an Advanced Persistent Threat performing container exec followed by network pivoting. Both signals arrive within the multi-signal correlation window, triggering a 2.5× score multiplier and escalating to human review.",
    difficulty: "HIGH",
    estimatedMinutes: 1,
    targetBucket: "human",
    icon: Target,
    steps: [
      {
        id: "step_exec",
        name: "Container Exec Injection",
        attack: "docker_exec",
        nodeSpecific: true,
        description: "Run `id` inside the target container via Docker exec API.",
        expectedAlert: "CONTAINER_EXEC + UNEXPECTED_EXEC",
        waitMs: 0,
        annotation:
          "The docker_collector detects the exec event and emits CONTAINER_EXEC. This is suspicious activity — processes are not expected to run inside compute nodes.",
      },
      {
        id: "step_drift",
        name: "Network Segment Pivot",
        attack: "runtime_drift_network",
        nodeSpecific: true,
        description: "Attach the container to the storage-net segment (not in baseline).",
        expectedAlert: "RUNTIME_DRIFT",
        waitMs: 5000,
        annotation:
          "The host-observer detects the network attachment differs from runtime_baseline.yaml. Combined with CONTAINER_EXEC within 120s, the multi-signal correlator fires the 'Active Attack Chain' rule at 2.5× multiplier.",
      },
    ],
  },
  {
    id: "supply_chain_compromise",
    name: "Supply Chain Compromise",
    description:
      "Simulates a compromised container image alongside policy file tampering, matching the 'Deployment Tamper' multi-signal correlation pattern and triggering critical enforcement.",
    difficulty: "CRITICAL",
    estimatedMinutes: 1,
    targetBucket: "quarantine",
    icon: ShieldAlert,
    steps: [
      {
        id: "step_image",
        name: "Image Digest Mismatch",
        attack: "image_mismatch",
        nodeSpecific: true,
        description: "Inject IMAGE_MISMATCH — running digest differs from approved_images.yaml.",
        expectedAlert: "IMAGE_MISMATCH",
        waitMs: 0,
        annotation:
          "The cluster_observer compares the running container's SHA-256 digest against the approved_images.yaml allowlist. A mismatch indicates a potentially tampered or substituted image.",
      },
      {
        id: "step_policy",
        name: "Policy File Tamper",
        attack: "config_tamper",
        nodeSpecific: false,
        description: "Simulate rules.yaml being modified on disk.",
        expectedAlert: "POLICY_TAMPER",
        waitMs: 3000,
        annotation:
          "The InfraConfigGuard detects the config hash mismatch. IMAGE_MISMATCH + RUNTIME_DRIFT within 600s matches the 'Deployment Tamper' correlation rule (2.0× multiplier) pushing the node into quarantine.",
      },
    ],
  },
  {
    id: "coordinated_intrusion",
    name: "Coordinated Intrusion",
    description:
      "A rogue node attempts to join the cluster while simultaneously replaying captured telemetry messages — matching the 'Coordinated Intrusion' multi-signal rule at a 3.0× score multiplier.",
    difficulty: "CRITICAL",
    estimatedMinutes: 1,
    targetBucket: "quarantine",
    icon: Activity,
    steps: [
      {
        id: "step_rogue",
        name: "Rogue Node Injection",
        attack: "rogue_node",
        nodeSpecific: false,
        description: "Send a signed ZMQ message from an unknown node ID to the controller.",
        expectedAlert: "ROGUE_NODE",
        waitMs: 0,
        annotation:
          "The controller's allowlist check fails — the unknown node ID is not in allowlist.yaml. The controller emits ROGUE_NODE and forwards it to the risk engine.",
      },
      {
        id: "step_replay",
        name: "Replay Attack",
        attack: "replay_attack",
        nodeSpecific: false,
        description: "Re-transmit a previously seen msg_id to the controller's ZMQ socket.",
        expectedAlert: "REPLAY_ATTACK",
        waitMs: 4000,
        annotation:
          "The ReplayGuard detects the duplicate msg_id. ALLOWLIST_TAMPER + ROGUE_NODE within 600s matches the 'Coordinated Intrusion' rule — 3.0× multiplier, immediate quarantine.",
      },
    ],
  },
];

const DIFFICULTY_CONFIG = {
  LOW:      { color: "text-green-400",  bg: "bg-green-500/10 ring-green-500/30" },
  MEDIUM:   { color: "text-yellow-400", bg: "bg-yellow-500/10 ring-yellow-500/30" },
  HIGH:     { color: "text-orange-400", bg: "bg-orange-500/10 ring-orange-500/30" },
  CRITICAL: { color: "text-red-400",    bg: "bg-red-500/10 ring-red-500/30" },
};

// ── Sub-components ───────────────────────────────────────────────────────────

type StepStatus = "idle" | "firing" | "success" | "error" | "waiting";

interface StepState {
  status: StepStatus;
  message: string;
  firedAt?: Date;
}

function NarrationStep({
  step,
  index,
  state,
  isLast,
}: {
  step: PlaybookStep;
  index: number;
  state: StepState;
  isLast: boolean;
}) {
  const { status } = state;

  const dotColor =
    status === "success" ? "bg-green-500" :
    status === "error"   ? "bg-red-500" :
    status === "firing"  ? "bg-amber-500 animate-pulse" :
    status === "waiting" ? "bg-zinc-600 animate-pulse" :
                           "bg-zinc-800";

  const borderColor =
    status === "success" ? "border-green-500/30" :
    status === "error"   ? "border-red-500/30" :
    status === "firing"  ? "border-amber-500/30" :
                           "border-zinc-800";

  return (
    <div className="relative flex gap-4">
      {/* Timeline vertical line */}
      {!isLast && (
        <div className="absolute left-5 top-10 bottom-0 w-px bg-zinc-800" />
      )}

      {/* Step number / status dot */}
      <div className="relative z-10 flex h-10 w-10 shrink-0 items-center justify-center">
        <div className={`h-4 w-4 rounded-full border-2 border-zinc-900 transition-all duration-300 ${dotColor}`} />
      </div>

      {/* Step content */}
      <div className={`mb-6 flex-1 rounded-xl border p-4 transition-all duration-300 ${borderColor} ${
        status === "firing" ? "bg-amber-500/5" :
        status === "success" ? "bg-green-500/5" :
        status === "idle" ? "bg-zinc-900/30 opacity-50" :
        "bg-zinc-900/50"
      }`}>
        <div className="flex items-start justify-between gap-2 mb-2">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-zinc-600">STEP {index + 1}</span>
              {status === "success" && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-green-400">
                  <CheckCircle2 className="h-3 w-3" /> Detected
                </span>
              )}
              {status === "firing" && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-amber-400">
                  <Loader2 className="h-3 w-3 animate-spin" /> Executing…
                </span>
              )}
              {status === "waiting" && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-zinc-500">
                  <Clock className="h-3 w-3" /> Waiting…
                </span>
              )}
              {status === "error" && (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-red-400">
                  <AlertTriangle className="h-3 w-3" /> Failed
                </span>
              )}
            </div>
            <h4 className="text-sm font-bold text-white mt-0.5">{step.name}</h4>
          </div>
          <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-400 ring-1 ring-zinc-700 shrink-0">
            {step.attack}
          </span>
        </div>

        <p className="text-xs text-zinc-500 mb-3">{step.description}</p>

        {/* Annotation — shows what the system detects */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-zinc-600 mb-1">
            System Response
          </div>
          <p className="text-[11px] text-zinc-400 leading-relaxed">{step.annotation}</p>
        </div>

        {/* Result message */}
        {state.message && status !== "idle" && (
          <div className={`mt-2 text-[11px] font-mono px-2 py-1 rounded border ${
            status === "success" ? "border-green-500/20 bg-green-500/10 text-green-400" :
            status === "error"   ? "border-red-500/20 bg-red-500/10 text-red-400" :
                                   "border-zinc-700 bg-zinc-900 text-zinc-500"
          }`}>
            {state.message}
          </div>
        )}

        {/* Expected alert chips */}
        <div className="mt-2 flex flex-wrap gap-1">
          {step.expectedAlert.split("+").map((a) => (
            <span key={a} className={`rounded px-1.5 py-0.5 font-mono text-[10px] ring-1 ${
              status === "success"
                ? "bg-green-500/15 text-green-400 ring-green-500/30"
                : "bg-zinc-800 text-zinc-500 ring-zinc-700"
            }`}>
              {a.trim()}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────────────────

export function ScenarioLauncher() {
  const [selectedScenario, setSelectedScenario] = useState<PlaybookScenario | null>(null);
  const [selectedNode, setSelectedNode] = useState("node1");
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [stepStates, setStepStates] = useState<StepState[]>([]);
  const abortRef = useRef(false);
  const { mutateAsync } = useSimulateAttack();
  const { data: nodesData } = useNodes();

  const nodes = nodesData?.map((n: { node: string }) => n.node) ?? ["node1", "node2", "node3", "node4"];

  const selectScenario = (scenario: PlaybookScenario) => {
    setSelectedScenario(scenario);
    setStepStates(scenario.steps.map(() => ({ status: "idle", message: "" })));
    setRunning(false);
    setDone(false);
    abortRef.current = false;
  };

  const setStep = (i: number, patch: Partial<StepState>) => {
    setStepStates((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));
  };

  const runScenario = async () => {
    if (!selectedScenario) return;
    abortRef.current = false;
    setRunning(true);
    setDone(false);
    setStepStates(selectedScenario.steps.map(() => ({ status: "idle", message: "" })));

    for (let i = 0; i < selectedScenario.steps.length; i++) {
      if (abortRef.current) break;
      const step = selectedScenario.steps[i];

      // Wait phase (narrative pacing)
      if (step.waitMs > 0) {
        setStep(i, { status: "waiting", message: `Waiting ${step.waitMs / 1000}s before next step…` });
        await new Promise((r) => setTimeout(r, step.waitMs));
      }

      if (abortRef.current) break;

      // Fire phase
      setStep(i, { status: "firing", message: "Firing…", firedAt: new Date() });

      try {
        const node = step.nodeSpecific ? selectedNode : undefined;
        const result = await mutateAsync({ attack: step.attack, node });
        setStep(i, {
          status: result.ok ? "success" : "error",
          message: result.message ?? (result.ok ? "Executed." : result.error ?? "Failed."),
          firedAt: new Date(),
        });
      } catch (err) {
        setStep(i, {
          status: "error",
          message: err instanceof Error ? err.message : "Network error",
        });
      }

      // Small gap between steps for readability
      if (i < selectedScenario.steps.length - 1) {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }

    setRunning(false);
    setDone(true);
  };

  const reset = () => {
    abortRef.current = true;
    if (selectedScenario) {
      setStepStates(selectedScenario.steps.map(() => ({ status: "idle", message: "" })));
    }
    setRunning(false);
    setDone(false);
  };

  const successCount = stepStates.filter((s) => s.status === "success").length;

  return (
    <div className="grid gap-8 xl:grid-cols-[360px_1fr]">
      {/* ── Scenario selector panel ── */}
      <div className="space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-zinc-300 mb-1">Select Scenario</h3>
          <p className="text-xs text-zinc-500">Choose an attack scenario to launch step-by-step with live narration.</p>
        </div>

        {/* Node picker */}
        <div>
          <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
            Target Node
          </label>
          <div className="relative">
            <select
              value={selectedNode}
              onChange={(e) => setSelectedNode(e.target.value)}
              className="w-full appearance-none rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 pr-8 text-sm text-zinc-200 focus:border-zinc-500 focus:outline-none"
            >
              {nodes.map((n: string) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          </div>
        </div>

        {/* Scenario cards */}
        <div className="space-y-3">
          {SCENARIOS.map((scenario) => {
            const Icon = scenario.icon;
            const cfg  = DIFFICULTY_CONFIG[scenario.difficulty];
            const isSelected = selectedScenario?.id === scenario.id;

            return (
              <button
                key={scenario.id}
                onClick={() => selectScenario(scenario)}
                className={`w-full rounded-xl border p-4 text-left transition-all duration-200 ${
                  isSelected
                    ? "border-cyan-500/40 bg-cyan-500/10 shadow-lg shadow-cyan-900/20"
                    : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 hover:bg-zinc-900/70"
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${isSelected ? "bg-cyan-500/20" : "bg-zinc-800"}`}>
                    <Icon className={`h-4 w-4 ${isSelected ? "text-cyan-400" : "text-zinc-400"}`} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-bold text-white truncate">{scenario.name}</span>
                      <span className={`shrink-0 rounded-md px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide ring-1 ${cfg.bg} ${cfg.color}`}>
                        {scenario.difficulty}
                      </span>
                    </div>
                    <p className="text-[11px] text-zinc-500 leading-relaxed line-clamp-2">{scenario.description}</p>
                    <div className="mt-2 flex items-center gap-3 text-[10px] text-zinc-600">
                      <span>{scenario.steps.length} steps</span>
                      <span>·</span>
                      <span>~{scenario.estimatedMinutes}min</span>
                      <span>·</span>
                      <span className="uppercase">{scenario.targetBucket} bucket</span>
                    </div>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Narration timeline panel ── */}
      <div className="space-y-6">
        {!selectedScenario ? (
          <div className="flex flex-col items-center justify-center rounded-2xl border border-zinc-800 bg-zinc-900/30 py-20 text-center">
            <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-zinc-800 ring-2 ring-zinc-700">
              <Target className="h-7 w-7 text-zinc-500" />
            </div>
            <p className="text-sm text-zinc-500">Select a scenario to begin</p>
          </div>
        ) : (
          <>
            {/* Scenario header */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className={`mb-2 inline-block rounded-md px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${DIFFICULTY_CONFIG[selectedScenario.difficulty].bg} ${DIFFICULTY_CONFIG[selectedScenario.difficulty].color}`}>
                    {selectedScenario.difficulty}
                  </div>
                  <h3 className="text-lg font-bold text-white">{selectedScenario.name}</h3>
                  <p className="mt-1 text-sm text-zinc-400">{selectedScenario.description}</p>
                </div>
                <div className="flex flex-col gap-2 shrink-0">
                  {!running && !done && (
                    <button
                      onClick={runScenario}
                      className="flex items-center gap-2 rounded-lg bg-red-600/90 px-5 py-2.5 text-sm font-bold text-white hover:bg-red-600 transition-colors shadow-lg shadow-red-900/30"
                    >
                      <Target className="h-4 w-4" />
                      Launch Scenario
                    </button>
                  )}
                  {(running || done) && (
                    <button
                      onClick={reset}
                      className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-zinc-300 hover:bg-zinc-800 transition-colors"
                    >
                      Reset
                    </button>
                  )}
                </div>
              </div>

              {/* Progress bar */}
              {(running || done) && selectedScenario.steps.length > 0 && (
                <div className="mt-4">
                  <div className="flex items-center justify-between text-[11px] text-zinc-500 mb-1.5">
                    <span>{successCount} / {selectedScenario.steps.length} steps complete</span>
                    {done && successCount === selectedScenario.steps.length && (
                      <span className="flex items-center gap-1 text-green-400 font-semibold">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Scenario Complete
                      </span>
                    )}
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
                      style={{ width: `${(successCount / selectedScenario.steps.length) * 100}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Step narration */}
            {stepStates.length > 0 && (
              <div className="space-y-0">
                {selectedScenario.steps.map((step, i) => (
                  <NarrationStep
                    key={step.id}
                    step={step}
                    index={i}
                    state={stepStates[i]}
                    isLast={i === selectedScenario.steps.length - 1}
                  />
                ))}
              </div>
            )}

            {/* Completion card */}
            {done && successCount === selectedScenario.steps.length && (
              <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <CheckCircle2 className="h-5 w-5 text-cyan-400" />
                  <span className="font-bold text-cyan-300">Scenario Complete</span>
                </div>
                <p className="text-sm text-zinc-400">
                  All steps executed. Check the{" "}
                  <span className="font-semibold text-amber-300">Human Review Queue</span>{" "}
                  or{" "}
                  <span className="font-semibold text-cyan-300">Nodes</span>{" "}
                  panel to see the enforcement response. The risk engine has processed the signals and taken action.
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
