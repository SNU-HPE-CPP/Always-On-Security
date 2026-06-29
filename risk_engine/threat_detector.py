"""
Always-On Security — Threat Detector

Infrastructure-side only. Tenant FIM and process denylist detections
have been intentionally removed. Process names are trivially spoofable.
Hashing tenant-owned files violates workload ownership.

Active detectors:
  A. Rogue Node                  — node not in allowlist
  B. Node Impersonation          — machine_id changed for known node
  C. Secondary Flood Check       — belt-and-suspenders rate check
  D. Lateral Movement            — unexpected SSH connections
  E. Network Threat              — from security monitor pipeline
  F. Silent Node                 — heartbeat timeout (from heartbeat thread)
  G. Telemetry Tamper            — caught at controller; re-validated here
  H. Image Mismatch / Unapproved — from host observer image attestation
  I. Runtime Drift               — from host observer runtime drift detector
  J. Infra Config Integrity      — CONFIG_DRIFT / POLICY_TAMPER / ALLOWLIST_TAMPER
  K. Docker Event Analytics      — CONTAINER_EXEC, UNEXPECTED_EXEC,
                                   SUSPICIOUS_RESTART_PATTERN, UNEXPECTED_NETWORK_ATTACH
  L. Falco Alerts                — FALCO_ALERT, REVERSE_SHELL, PRIV_ESC_ATTEMPT,
                                   CONTAINER_ESCAPE_ATTEMPT
"""

import logging
import os
import time
from collections import defaultdict, deque

import yaml

from alert_manager import ThreatSignal

log = logging.getLogger("threat_detector")

_ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/opt/security/config/allowlist.yaml")

# Event types routed directly from host observer / security monitor
# that carry pre-built evidence and just need scoring
_PASSTHROUGH_EVENTS = {
    "IMAGE_MISMATCH",
    "UNAPPROVED_IMAGE",
    "IMAGE_DRIFT",
    "RUNTIME_DRIFT",
    "CONFIG_DRIFT",
    "POLICY_TAMPER",
    "ALLOWLIST_TAMPER",
    "CONTAINER_EXEC",
    "UNEXPECTED_EXEC",
    "SUSPICIOUS_RESTART_PATTERN",
    "UNEXPECTED_NETWORK_ATTACH",
    "FALCO_ALERT",
    "REVERSE_SHELL",
    "PRIV_ESC_ATTEMPT",
    "CONTAINER_ESCAPE_ATTEMPT",
}

# Default severity for each event type
_PASSTHROUGH_SEVERITY = {
    "IMAGE_MISMATCH":              "HIGH",
    "UNAPPROVED_IMAGE":            "HIGH",
    "IMAGE_DRIFT":                 "HIGH",
    "RUNTIME_DRIFT":               "HIGH",
    "CONFIG_DRIFT":                "HIGH",
    "POLICY_TAMPER":               "CRITICAL",
    "ALLOWLIST_TAMPER":            "CRITICAL",
    "CONTAINER_EXEC":              "MEDIUM",
    "UNEXPECTED_EXEC":             "HIGH",
    "SUSPICIOUS_RESTART_PATTERN":  "MEDIUM",
    "UNEXPECTED_NETWORK_ATTACH":   "HIGH",
    "FALCO_ALERT":                 "HIGH",
    "REVERSE_SHELL":               "CRITICAL",
    "PRIV_ESC_ATTEMPT":            "CRITICAL",
    "CONTAINER_ESCAPE_ATTEMPT":    "CRITICAL",
}


def _load_config() -> dict:
    try:
        with open(_ALLOWLIST_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.warning(f"Could not load allowlist config: {e}")
        return {}


class ThreatDetector:
    def __init__(self, store):
        self._store = store
        cfg         = _load_config()
        self._allowed_nodes      = set(cfg.get("allowed_nodes", []))
        flood_cfg                = cfg.get("flood_threshold", {})
        self._flood_max_per_60s  = int(flood_cfg.get("max_msgs_per_60s", 20))
        hb_cfg                   = cfg.get("heartbeat_timeout_seconds", {})
        self._hb_default         = int(hb_cfg.get("default", 30))
        self._hb_per_node        = {k: int(v) for k, v in hb_cfg.items() if k != "default"}
        self._flood_times: dict[str, deque] = defaultdict(deque)

        log.info(
            f"ThreatDetector ready | allowed={self._allowed_nodes} | "
            f"flood_max={self._flood_max_per_60s}/60s"
        )

    def run(self, event: dict) -> list:
        if event.get("security_alert"):
            return [ThreatSignal(
                node_id     = event.get("node", "unknown"),
                threat_type = event.get("threat_type", "UNKNOWN"),
                severity    = event.get("severity", "CRITICAL"),
                description = event.get("description", ""),
                evidence    = event.get("evidence", {}),
            )]

        node    = event.get("node", "unknown")
        signals = []

        # Infrastructure detections that carry full evidence from host observer
        event_type = event.get("event_type", "NORMAL")
        if event_type in _PASSTHROUGH_EVENTS:
            signals += self._detect_infra_event(node, event, event_type)
            return signals  # No need to run other detectors on these

        signals += self._detect_rogue_node(node, event)
        signals += self._detect_impersonation(node, event)
        signals += self._detect_secondary_flood(node, event)
        signals += self._detect_lateral_movement(node, event)
        signals += self._detect_network_threat(node, event)

        return signals

    # ── Infrastructure pass-through events ───────────────────────────────────

    def _detect_infra_event(self, node: str, event: dict, event_type: str) -> list:
        """
        Convert a host-observer / security-monitor infrastructure event into a
        ThreatSignal. Evidence is already fully populated by the emitting module.
        """
        severity = _PASSTHROUGH_SEVERITY.get(event_type, "MEDIUM")
        reasons  = event.get("reasons", [event_type])
        evidence = event.get("evidence", {})

        log.warning(f"[{event_type}] node={node}")
        return [ThreatSignal(
            node_id     = node,
            threat_type = event_type,
            severity    = severity,
            description = reasons[0] if reasons else event_type,
            evidence    = evidence,
        )]

    # ── A: Rogue Node ─────────────────────────────────────────────────────────

    def _detect_rogue_node(self, node: str, event: dict) -> list:
        if not self._allowed_nodes:
            return []
        if node not in self._allowed_nodes:
            log.warning(f"[ENGINE] ROGUE_NODE: {node}")
            return [ThreatSignal(
                node_id     = node,
                threat_type = "ROGUE_NODE",
                severity    = "CRITICAL",
                description = f"Node '{node}' is not in the approved allowlist.",
                evidence    = {
                    "node":       node,
                    "machine_id": event.get("machine_id", ""),
                    "allowed":    list(self._allowed_nodes),
                },
            )]
        return []

    # ── B: Node Impersonation ─────────────────────────────────────────────────

    def _detect_impersonation(self, node: str, event: dict) -> list:
        claimed_mid = event.get("machine_id", "")
        if not claimed_mid:
            return []
        known = self._store.get_node_identity(node)
        if known is None:
            self._store.upsert_node_identity(node=node, machine_id=claimed_mid, trust_status="TRUSTED")
            return []
        known_mid = known.get("machine_id", "")
        if known_mid and known_mid != claimed_mid:
            log.warning(f"[ENGINE] NODE_IMPERSONATION: {node} machine_id changed")
            self._store.upsert_node_identity(node=node, machine_id=claimed_mid, trust_status="SUSPECT")
            return [ThreatSignal(
                node_id     = node,
                threat_type = "NODE_IMPERSONATION",
                severity    = "CRITICAL",
                description = f"Node {node} changed its machine_id.",
                evidence    = {
                    "node":              node,
                    "known_machine_id":  known_mid,
                    "claimed_machine_id": claimed_mid,
                },
            )]
        self._store.upsert_node_identity(
            node=node, machine_id=claimed_mid,
            trust_status=known.get("trust_status", "TRUSTED"),
        )
        return []

    # ── C: Secondary Flood Check ──────────────────────────────────────────────

    def _detect_secondary_flood(self, node: str, event: dict) -> list:
        now    = time.time()
        cutoff = now - 60
        dq     = self._flood_times[node]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        count     = len(dq)
        threshold = self._flood_max_per_60s * 2
        if count > threshold:
            return [ThreatSignal(
                node_id     = node,
                threat_type = "FLOOD_ATTACK",
                severity    = "MEDIUM",
                description = f"Engine: flood from {node}: {count} msgs/60s (threshold={threshold})",
                evidence    = {"node": node, "count": count, "threshold": threshold},
            )]
        return []

    # ── D: Lateral Movement ───────────────────────────────────────────────────

    def _detect_lateral_movement(self, node: str, event: dict) -> list:
        ssh_count  = int(event.get("ssh_connections", 0))
        peers      = event.get("lateral_peers", [])
        peer_count = int(event.get("peer_contact_count", 0))
        if ssh_count <= 0:
            return []
        log.warning(f"[ENGINE] LATERAL_MOVEMENT: {node} has {ssh_count} SSH connections")
        return [ThreatSignal(
            node_id     = node,
            threat_type = "LATERAL_MOVEMENT",
            severity    = "HIGH",
            description = f"Node {node} has {ssh_count} unexpected SSH connections to {peer_count} peer(s).",
            evidence    = {
                "node":         node,
                "ssh_count":    ssh_count,
                "peer_count":   peer_count,
                "lateral_peers": peers,
            },
        )]

    # ── E: Network Threat ────────────────────────────────────────────────────

    def _detect_network_threat(self, node: str, event: dict) -> list:
        if not event.get("network_threat"):
            return []
        anomalies = event.get("network_anomalies", [])
        if not anomalies:
            return []
        listeners  = event.get("unexpected_listeners", [])
        egress     = event.get("unexpected_egress", [])
        target_cnt = int(event.get("remote_target_count", 0))
        conn_cnt   = int(event.get("remote_connection_count", 0))
        log.warning(f"[ENGINE] NETWORK_THREAT: {node} — {anomalies}")
        return [ThreatSignal(
            node_id     = node,
            threat_type = "NETWORK_THREAT",
            severity    = "HIGH",
            description = (
                f"Node {node} has suspicious network activity: "
                f"{len(anomalies)} anomaly(s), {conn_cnt} TCP connection(s)."
            ),
            evidence    = {
                "node":                    node,
                "anomalies":               anomalies,
                "unexpected_listeners":    listeners,
                "unexpected_egress":       egress,
                "remote_connection_count": conn_cnt,
                "remote_target_count":     target_cnt,
            },
        )]

    # ── F: Silent Node (called externally from heartbeat thread) ─────────────

    def build_silent_node_signal(self, node: str, delta_seconds: float) -> ThreatSignal:
        hb_timeout = self._hb_per_node.get(node, self._hb_default)
        return ThreatSignal(
            node_id     = node,
            threat_type = "SILENT_NODE",
            severity    = "HIGH",
            description = (
                f"Node {node} has not reported for {delta_seconds:.0f}s "
                f"(timeout={hb_timeout}s)."
            ),
            evidence    = {
                "node":               node,
                "silent_seconds":     round(delta_seconds, 1),
                "configured_timeout": hb_timeout,
            },
        )
