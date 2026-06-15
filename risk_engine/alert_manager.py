"""
Always-On Security — Alert Manager

Unified alert model for all security threat detections.
Each alert is:
  • Stored in the `security_alerts` SQLite table
  • Logged at the appropriate level
  • Optionally triggers escalation actions based on severity
"""

import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("alert_manager")

# ─────────────────────────────────────────
# Severity levels (ordered)
# ─────────────────────────────────────────

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Recommended actions by severity (default — overridden per threat type)
SEVERITY_ACTIONS: dict[str, str] = {
    "INFO":     "Log and monitor.",
    "LOW":      "Review during next maintenance window.",
    "MEDIUM":   "Investigate within 4 hours. Consider rate limiting.",
    "HIGH":     "Investigate immediately. Consider isolating the node.",
    "CRITICAL": "Quarantine the node immediately and initiate incident response.",
}

# ─────────────────────────────────────────
# Alert dataclass
# ─────────────────────────────────────────

@dataclass
class SecurityAlert:
    """
    Unified security alert model.
    All fields must be populated — no optional evidence.
    """
    alert_id:           str   # UUID4
    timestamp:          str   # UTC ISO-8601
    node_id:            str
    severity:           str   # INFO | LOW | MEDIUM | HIGH | CRITICAL
    threat_type:        str   # e.g. ROGUE_NODE, REPLAY_ATTACK ...
    description:        str   # Human-readable summary
    evidence:           dict  # Structured evidence dict
    recommended_action: str


# ─────────────────────────────────────────
# Threat signal (produced by ThreatDetector)
# ─────────────────────────────────────────

@dataclass
class ThreatSignal:
    """
    Intermediate result produced by each detector function.
    AlertManager converts these into SecurityAlert records.
    """
    node_id:     str
    threat_type: str
    severity:    str
    description: str
    evidence:    dict
    recommended_action: str = ""


# ─────────────────────────────────────────
# Threat type → default severity mapping
# ─────────────────────────────────────────

THREAT_SEVERITY: dict[str, str] = {
    "ROGUE_NODE":          "CRITICAL",
    "NODE_IMPERSONATION":  "CRITICAL",
    "DUPLICATE_NODE_ID":   "HIGH",
    "REPLAY_ATTACK":       "HIGH",
    "FLOOD_ATTACK":        "MEDIUM",
    "SILENT_NODE":         "HIGH",
    "TELEMETRY_TAMPER":    "HIGH",
    "UNAUTH_PROCESS":      "MEDIUM",
    "LATERAL_MOVEMENT":    "HIGH",
    "CONFIG_TAMPER":       "HIGH",
    "NETWORK_THREAT":      "HIGH",
}

THREAT_ACTIONS: dict[str, str] = {
    "ROGUE_NODE":
        "Block node immediately. Identify its physical location and isolate.",
    "NODE_IMPERSONATION":
        "Quarantine node. Verify hardware identity out-of-band. Rotate HMAC secrets.",
    "DUPLICATE_NODE_ID":
        "Identify the conflicting source. One of the nodes may be compromised.",
    "REPLAY_ATTACK":
        "Reject message. Investigate if an attacker captured telemetry traffic.",
    "FLOOD_ATTACK":
        "Rate-limit or quarantine node. Investigate DoS intent.",
    "SILENT_NODE":
        "Verify node is reachable. Check for hardware failure or network partition.",
    "TELEMETRY_TAMPER":
        "Investigate node for compromise or man-in-the-middle attack.",
    "UNAUTH_PROCESS":
        "Kill the process. Investigate what deployed it. Check for malware.",
    "LATERAL_MOVEMENT":
        "Isolate node. Audit SSH keys. Check for credential theft.",
    "CONFIG_TAMPER":
        "Restore config from golden baseline. Investigate who modified the file.",
    "NETWORK_THREAT":
        "Isolate node. Inspect outbound connections, listeners, and firewall policy.",
}


# ─────────────────────────────────────────
# AlertManager
# ─────────────────────────────────────────

class AlertManager:
    """
    Creates, persists, and dispatches SecurityAlert records.
    Requires a Store instance for DB writes.
    """

    def __init__(self, store):
        self._store = store
        log.info("AlertManager initialised.")

    def emit(self, signal: ThreatSignal) -> SecurityAlert:
        """Convert a ThreatSignal into a SecurityAlert and persist it."""
        severity = signal.severity or THREAT_SEVERITY.get(signal.threat_type, "MEDIUM")
        action   = signal.recommended_action or THREAT_ACTIONS.get(
            signal.threat_type,
            SEVERITY_ACTIONS.get(severity, "Investigate."),
        )

        alert = SecurityAlert(
            alert_id           = str(uuid.uuid4()),
            timestamp          = datetime.now(timezone.utc).isoformat(),
            node_id            = signal.node_id,
            severity           = severity,
            threat_type        = signal.threat_type,
            description        = signal.description,
            evidence           = signal.evidence,
            recommended_action = action,
        )

        self._log(alert)
        try:
            self._store.write_alert(alert)
        except Exception as e:
            log.error(f"Failed to persist alert {alert.alert_id}: {e}")

        return alert

    def emit_batch(self, signals: list) -> list:
        """Emit multiple signals; returns list of SecurityAlert objects."""
        return [self.emit(s) for s in signals]

    def emit_from_event(self, event: dict) -> Optional[SecurityAlert]:
        """
        If the event carries a pre-built security alert (injected by controller),
        persist it directly without re-detection.
        """
        if not event.get("security_alert"):
            return None

        signal = ThreatSignal(
            node_id     = event.get("node_id") or event.get("node", "unknown"),
            threat_type = event.get("threat_type", "UNKNOWN"),
            severity    = event.get("severity", "MEDIUM"),
            description = event.get("description", ""),
            evidence    = event.get("evidence", {}),
            recommended_action = event.get("recommended_action", ""),
        )
        return self.emit(signal)


    # ── Private ───────────────────────────────────

    def _log(self, alert: SecurityAlert) -> None:
        level_map = {
            "INFO":     log.info,
            "LOW":      log.info,
            "MEDIUM":   log.warning,
            "HIGH":     log.error,
            "CRITICAL": log.critical,
        }
        fn = level_map.get(alert.severity, log.warning)
        fn(
            f"[{alert.severity}] [{alert.threat_type}] "
            f"node={alert.node_id} | {alert.description} | "
            f"alert_id={alert.alert_id}"
        )
