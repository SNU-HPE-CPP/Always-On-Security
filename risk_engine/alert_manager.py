"""
Always-On Security — Alert Manager
Unified alert model and persistence for all security threat detections.
"""
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("alert_manager")

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

THREAT_SEVERITY: dict = {
    "ROGUE_NODE": "CRITICAL", "NODE_IMPERSONATION": "CRITICAL",
    "DUPLICATE_NODE_ID": "HIGH", "REPLAY_ATTACK": "HIGH",
    "FLOOD_ATTACK": "MEDIUM", "SILENT_NODE": "HIGH",
    "TELEMETRY_TAMPER": "HIGH", "UNAUTH_PROCESS": "MEDIUM",
    "LATERAL_MOVEMENT": "HIGH", "CONFIG_TAMPER": "HIGH",
}

THREAT_ACTIONS: dict = {
    "ROGUE_NODE":         "Block node immediately. Identify its physical location and isolate.",
    "NODE_IMPERSONATION": "Quarantine node. Verify hardware identity out-of-band. Rotate HMAC secrets.",
    "DUPLICATE_NODE_ID":  "Identify the conflicting source. One of the nodes may be compromised.",
    "REPLAY_ATTACK":      "Reject message. Investigate if an attacker captured telemetry traffic.",
    "FLOOD_ATTACK":       "Rate-limit or quarantine node. Investigate DoS intent.",
    "SILENT_NODE":        "Verify node is reachable. Check for hardware failure or network partition.",
    "TELEMETRY_TAMPER":   "Investigate node for compromise or man-in-the-middle attack.",
    "UNAUTH_PROCESS":     "Kill the process. Investigate what deployed it. Check for malware.",
    "LATERAL_MOVEMENT":   "Isolate node. Audit SSH keys. Check for credential theft.",
    "CONFIG_TAMPER":      "Restore config from golden baseline. Investigate who modified the file.",
}


@dataclass
class SecurityAlert:
    alert_id: str
    timestamp: str
    node_id: str
    severity: str
    threat_type: str
    description: str
    evidence: dict
    recommended_action: str


@dataclass
class ThreatSignal:
    node_id: str
    threat_type: str
    severity: str
    description: str
    evidence: dict
    recommended_action: str = ""


class AlertManager:
    def __init__(self, store):
        self._store = store

    def emit(self, signal: ThreatSignal) -> SecurityAlert:
        severity = signal.severity or THREAT_SEVERITY.get(signal.threat_type, "MEDIUM")
        action   = signal.recommended_action or THREAT_ACTIONS.get(signal.threat_type, "Investigate.")
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            node_id=signal.node_id,
            severity=severity,
            threat_type=signal.threat_type,
            description=signal.description,
            evidence=signal.evidence,
            recommended_action=action,
        )
        level_map = {"INFO": log.info, "LOW": log.info, "MEDIUM": log.warning,
                     "HIGH": log.error, "CRITICAL": log.critical}
        level_map.get(severity, log.warning)(
            f"[{severity}] [{alert.threat_type}] node={alert.node_id} | {alert.description}"
        )
        try:
            self._store.write_alert(alert)
        except Exception as e:
            log.error(f"Failed to persist alert {alert.alert_id}: {e}")
        return alert

    def emit_batch(self, signals: list) -> list:
        return [self.emit(s) for s in signals]

    def emit_from_event(self, event: dict) -> Optional[SecurityAlert]:
        if not event.get("security_alert"):
            return None
        return self.emit(ThreatSignal(
            node_id=event.get("node", "unknown"),
            threat_type=event.get("threat_type", "UNKNOWN"),
            severity=event.get("severity", "MEDIUM"),
            description=event.get("description", ""),
            evidence=event.get("evidence", {}),
            recommended_action=event.get("recommended_action", ""),
        ))
