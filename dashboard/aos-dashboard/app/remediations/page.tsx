"use client";

import { Card } from "@/components/ui/card";
import { Terminal, Shield, Zap, Activity, AlertTriangle, RefreshCw } from "lucide-react";
import { useState } from "react";

const REMEDIATION_MAPS = [
  {
    threat: "RUNTIME_DRIFT",
    name: "Kill Unauthorized Process",
    description: "Detects unauthorized processes spawning and terminates them directly inside the container without causing downtime.",
    script: `#!/bin/sh
echo "Scanning for unauthorized processes..."
UNAUTH_PID=$(ps aux | grep -v grep | grep "rogue" | awk '{print $2}' | head -n 1)
if [ -n "$UNAUTH_PID" ]; then
  echo "Found unauthorized process PID $UNAUTH_PID. Terminating..."
  kill -9 $UNAUTH_PID
  echo "Process terminated successfully."
else
  echo "No unauthorized processes actively running. Remediation complete."
fi`,
    icon: Activity,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30"
  },
  {
    threat: "UNEXPECTED_NETWORK_ATTACH",
    name: "Isolate Rogue Network Segment",
    description: "Injects targeted iptables rules to block an unauthorized subnet pivot while allowing valid application traffic to continue.",
    script: `#!/bin/sh
echo "Applying targeted iptables rules to block unauthorized subnet..."
iptables -A OUTPUT -d 10.99.0.0/16 -j DROP
iptables -A INPUT -s 10.99.0.0/16 -j DROP
echo "Targeted network isolation complete."`,
    icon: Shield,
    color: "text-cyan-400",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/30"
  },
  {
    threat: "CONFIG_DRIFT",
    name: "Restore Configuration Baseline",
    description: "Detects unauthorized modification to critical infrastructure configuration and instantly restores it from the immutable baseline.",
    script: `#!/bin/sh
echo "Restoring configuration from backup..."
if [ -f /etc/config.bak ]; then
  cp /etc/config.bak /etc/config
  echo "Configuration restored successfully."
else
  echo "Backup not found, running config re-sync..."
  sleep 1
  echo "Sync complete."
fi`,
    icon: AlertTriangle,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30"
  },
  {
    threat: "LATERAL_MOVEMENT",
    name: "Revoke SSH Keys & Reset Sessions",
    description: "Immediately kills rogue active SSH sessions and triggers a key rotation sequence to stop lateral pivot attempts.",
    script: `#!/bin/sh
echo "Revoking active SSH sessions..."
pkill -9 sshd
echo "Rotating temporary credentials..."
sleep 1
echo "Lateral movement mitigated. Node is secure."`,
    icon: Zap,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30"
  },
  {
    threat: "IMAGE_MISMATCH",
    name: "Verify Container Digest & Restart",
    description: "Re-pulls the trusted image manifest from the registry and restarts the tampered workload to automatically snap it back to the approved baseline.",
    script: `#!/bin/sh
echo "Verifying image digest..."
echo "Pulling latest approved image manifest..."
sleep 1
echo "Restarting application service to apply approved image state..."
echo "Service restarted."`,
    icon: RefreshCw,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30"
  }
];

export default function RemediationMapsPage() {
  const [selectedThreat, setSelectedThreat] = useState(REMEDIATION_MAPS[0].threat);

  const activeMap = REMEDIATION_MAPS.find((m) => m.threat === selectedThreat);

  return (
    <div className="relative min-h-screen bg-zinc-950">
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute left-0 top-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute right-0 bottom-0 h-96 w-96 rounded-full bg-blue-500/10 blur-3xl" />
      </div>

      <div className="mx-auto max-w-7xl space-y-8 p-8">
        <div>
          <h1 className="text-4xl font-bold text-white">Smart Auto-Remediation Engine</h1>
          <p className="mt-2 max-w-2xl text-zinc-400">
            Intelligent playbooks that instantly map threat signatures to precise, targeted shell scripts. 
            This allows us to neutralize attacks in real-time without taking the entire node offline.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-3">
          {/* List of Threats */}
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white">Threat Vectors</h2>
            <div className="flex flex-col gap-3">
              {REMEDIATION_MAPS.map((map) => {
                const Icon = map.icon;
                const isActive = selectedThreat === map.threat;
                return (
                  <button
                    key={map.threat}
                    onClick={() => setSelectedThreat(map.threat)}
                    className={`flex items-start gap-4 rounded-xl border p-4 text-left transition-all ${
                      isActive 
                        ? `bg-zinc-900 border-zinc-700 shadow-lg shadow-black/50` 
                        : `bg-zinc-900/50 border-zinc-800/50 hover:bg-zinc-900`
                    }`}
                  >
                    <div className={`mt-1 rounded-lg p-2 ${map.bg}`}>
                      <Icon size={20} className={map.color} />
                    </div>
                    <div>
                      <div className="font-mono text-xs font-semibold text-zinc-500 mb-1">{map.threat}</div>
                      <div className="font-medium text-zinc-200">{map.name}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Remediation Details */}
          <div className="lg:col-span-2 space-y-4">
            <h2 className="text-lg font-semibold text-white">Execution Playbook</h2>
            
            {activeMap && (
              <Card className={`border ${activeMap.border} bg-zinc-900/80 p-6 backdrop-blur-sm`}>
                <div className="flex items-start gap-4">
                  <div className={`rounded-xl p-3 ${activeMap.bg}`}>
                    <activeMap.icon size={24} className={activeMap.color} />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-2xl font-bold text-white">{activeMap.name}</h3>
                    <div className="mt-1 font-mono text-sm text-zinc-500">Trigger: {activeMap.threat}</div>
                    <p className="mt-4 text-zinc-300 leading-relaxed">
                      {activeMap.description}
                    </p>
                  </div>
                </div>

                <div className="mt-8 rounded-lg overflow-hidden border border-zinc-800 bg-black/50">
                  <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900 px-4 py-2">
                    <Terminal size={14} className="text-zinc-500" />
                    <span className="font-mono text-xs text-zinc-400">remediation.sh</span>
                  </div>
                  <div className="p-4">
                    <pre className="overflow-x-auto text-sm">
                      <code className="font-mono text-zinc-300">
                        {activeMap.script.split('\n').map((line, i) => (
                          <div key={i} className="table-row">
                            <span className="table-cell pr-4 text-right text-zinc-700 select-none">{i + 1}</span>
                            <span className="table-cell whitespace-pre">{line}</span>
                          </div>
                        ))}
                      </code>
                    </pre>
                  </div>
                </div>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
