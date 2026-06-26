"""
Always-On Security — LLM-Free Incident Summary Generator

Generates structured, plain-English incident summaries from raw DB data.
No external AI/LLM services required — pure Python template logic.

Output is a dict used by the /api/incident-summary/<node> endpoint.
"""

import json
from datetime import datetime, timezone
from typing import Any


# ── MITRE ATT&CK mappings ────────────────────────────────────────────────────

MITRE_MAP: dict[str, dict[str, str]] = {
    "CONTAINER_EXEC":             {"id": "T1609",  "name": "Container Administration Command"},
    "UNEXPECTED_EXEC":            {"id": "T1609",  "name": "Container Administration Command"},
    "REVERSE_SHELL":              {"id": "T1059",  "name": "Command and Scripting Interpreter"},
    "PRIV_ESC_ATTEMPT":           {"id": "T1611",  "name": "Escape to Host"},
    "CONTAINER_ESCAPE_ATTEMPT":   {"id": "T1611",  "name": "Escape to Host"},
    "LATERAL_MOVEMENT":           {"id": "T1021",  "name": "Remote Services"},
    "NETWORK_THREAT":             {"id": "T1071",  "name": "Application Layer Protocol"},
    "RUNTIME_DRIFT":              {"id": "T1610",  "name": "Deploy Container"},
    "IMAGE_MISMATCH":             {"id": "T1525",  "name": "Implant Internal Image"},
    "UNAPPROVED_IMAGE":           {"id": "T1525",  "name": "Implant Internal Image"},
    "CONFIG_DRIFT":               {"id": "T1565",  "name": "Data Manipulation"},
    "POLICY_TAMPER":              {"id": "T1565",  "name": "Data Manipulation"},
    "ALLOWLIST_TAMPER":           {"id": "T1565",  "name": "Data Manipulation"},
    "ROGUE_NODE":                 {"id": "T1078",  "name": "Valid Accounts"},
    "REPLAY_ATTACK":              {"id": "T1557",  "name": "Adversary-in-the-Middle"},
    "FLOOD_ATTACK":               {"id": "T1499",  "name": "Endpoint Denial of Service"},
    "NODE_IMPERSONATION":         {"id": "T1078",  "name": "Valid Accounts"},
    "TELEMETRY_TAMPER":           {"id": "T1565",  "name": "Data Manipulation"},
    "SILENT_NODE":                {"id": "T1489",  "name": "Service Stop"},
    "SUSPICIOUS_RESTART_PATTERN": {"id": "T1499",  "name": "Endpoint Denial of Service"},
    "FALCO_ALERT":                {"id": "T1059",  "name": "Command and Scripting Interpreter"},
    "UNEXPECTED_NETWORK_ATTACH":  {"id": "T1021",  "name": "Remote Services"},
}

# ── NIST SP 800-234 control mappings ─────────────────────────────────────────

NIST_MAP: dict[str, list[str]] = {
    "CONTAINER_EXEC":             ["SI-3", "CM-7"],
    "UNEXPECTED_EXEC":            ["SI-3", "CM-7"],
    "REVERSE_SHELL":              ["SI-3", "IR-4"],
    "PRIV_ESC_ATTEMPT":           ["AC-6", "IR-4"],
    "CONTAINER_ESCAPE_ATTEMPT":   ["SC-39", "IR-4"],
    "LATERAL_MOVEMENT":           ["SC-7", "AC-4"],
    "NETWORK_THREAT":             ["SC-7", "SI-4"],
    "RUNTIME_DRIFT":              ["CM-2", "CM-6"],
    "IMAGE_MISMATCH":             ["CM-5", "SI-7"],
    "UNAPPROVED_IMAGE":           ["CM-5", "SI-7"],
    "CONFIG_DRIFT":               ["CM-2", "SI-7"],
    "POLICY_TAMPER":              ["CM-6", "SI-7"],
    "ALLOWLIST_TAMPER":           ["AC-3", "SI-7"],
    "ROGUE_NODE":                 ["IA-3", "AC-3"],
    "REPLAY_ATTACK":              ["IA-8", "SC-8"],
    "FLOOD_ATTACK":               ["SC-5", "IR-4"],
    "NODE_IMPERSONATION":         ["IA-3", "AU-3"],
    "TELEMETRY_TAMPER":           ["SI-7", "AU-9"],
    "SILENT_NODE":                ["SI-4", "IR-5"],
    "SUSPICIOUS_RESTART_PATTERN": ["SI-3", "IR-5"],
    "FALCO_ALERT":                ["SI-4", "AU-12"],
    "UNEXPECTED_NETWORK_ATTACH":  ["SC-7", "CM-2"],
}

# ── Multi-signal correlation rule labels ─────────────────────────────────────

MULTI_SIGNAL_LABELS: list[tuple[frozenset, str, float]] = [
    (frozenset({"REVERSE_SHELL", "NETWORK_THREAT"}),             "High Confidence Compromise",  2.5),
    (frozenset({"FALCO_ALERT", "RUNTIME_DRIFT", "NETWORK_THREAT"}), "Critical Multi-Signal Risk", 3.0),
    (frozenset({"CONTAINER_EXEC", "PRIV_ESC_ATTEMPT"}),          "Active Attack Chain",          2.5),
    (frozenset({"IMAGE_MISMATCH", "RUNTIME_DRIFT"}),             "Deployment Tamper",            2.0),
    (frozenset({"ALLOWLIST_TAMPER", "ROGUE_NODE"}),              "Coordinated Intrusion",        3.0),
    (frozenset({"CONTAINER_ESCAPE_ATTEMPT", "PRIV_ESC_ATTEMPT"}), "Container Escape Attempt",    3.0),
]

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

RECOMMENDED_ACTION_RULES: list[tuple[list[str], str]] = [
    (["CONTAINER_ESCAPE_ATTEMPT", "REVERSE_SHELL", "PRIV_ESC_ATTEMPT"], "QUARANTINE"),
    (["ALLOWLIST_TAMPER", "POLICY_TAMPER", "ROGUE_NODE", "NODE_IMPERSONATION"], "QUARANTINE"),
    (["IMAGE_MISMATCH", "UNAPPROVED_IMAGE"], "QUARANTINE"),
    (["RUNTIME_DRIFT", "NETWORK_THREAT", "LATERAL_MOVEMENT"], "INVESTIGATE_FURTHER"),
    (["CONFIG_DRIFT", "FALCO_ALERT", "CONTAINER_EXEC"], "INVESTIGATE_FURTHER"),
]


def _parse_json_field(val: Any, default: Any) -> Any:
    if val is None:
        return default
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return default


def _fmt_ts(ts_str: str) -> str:
    """Format ISO timestamp to human-readable short form."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S UTC")
    except Exception:
        return ts_str


def _ago(ts_str: str) -> str:
    """Return human-readable relative time string."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = int((now - dt).total_seconds())
        if delta < 60:
            return f"{delta}s ago"
        if delta < 3600:
            return f"{delta // 60}m ago"
        return f"{delta // 3600}h {(delta % 3600) // 60}m ago"
    except Exception:
        return ""


def _detect_correlations(threat_types: set[str]) -> list[dict]:
    """Find all multi-signal correlation rules that match the observed threat types."""
    matches = []
    for required, label, multiplier in MULTI_SIGNAL_LABELS:
        if required.issubset(threat_types):
            matches.append({
                "label": label,
                "multiplier": multiplier,
                "matched_types": sorted(required),
            })
    return matches


def _determine_recommended_action(threat_types: set[str], risk_score: float, correlations: list) -> str:
    # High score always → quarantine
    if risk_score > 100:
        return "QUARANTINE"
    # Check rule-based overrides
    for triggers, action in RECOMMENDED_ACTION_RULES:
        if any(t in threat_types for t in triggers):
            return action
    # Correlation-driven
    if any(c["multiplier"] >= 2.5 for c in correlations):
        return "QUARANTINE"
    if correlations:
        return "INVESTIGATE_FURTHER"
    if risk_score >= 71:
        return "INVESTIGATE_FURTHER"
    return "APPROVE_AND_RESUME"


def _build_narrative(
    node: str,
    risk_score: float,
    top_threats: list[dict],
    correlations: list[dict],
    enforcement: list[str],
    paused_at: str,
    event_count: int,
) -> str:
    """Generate a 3-4 sentence plain-English narrative of the incident."""

    # Sentence 1 — what happened and when
    paused_str = _fmt_ts(paused_at) if paused_at else "an unknown time"
    s1 = (
        f"Node **{node}** was escalated to human review at {paused_str} "
        f"with a cumulative risk score of **{risk_score:.1f}**."
    )

    # Sentence 2 — what was detected
    if top_threats:
        top_names = ", ".join(f"`{t['threat_type']}`" for t in top_threats[:3])
        s2 = (
            f"The detection pipeline recorded **{event_count}** scored events, "
            f"with the dominant threat signals being {top_names}."
        )
    else:
        s2 = f"The detection pipeline recorded **{event_count}** scored events."

    # Sentence 3 — correlation finding (if any)
    if correlations:
        best = max(correlations, key=lambda c: c["multiplier"])
        matched = " + ".join(f"`{t}`" for t in best["matched_types"])
        s3 = (
            f"Multi-signal correlation engine matched the **{best['label']}** pattern "
            f"({matched}, {best['multiplier']}× score multiplier), "
            f"indicating a high-confidence coordinated threat."
        )
    else:
        s3 = (
            "No multi-signal correlation patterns were matched; "
            "the escalation was triggered by cumulative threshold breach."
        )

    # Sentence 4 — what the system did
    if enforcement:
        actions_str = " and ".join(enforcement)
        s4 = (
            f"The system automatically {actions_str}. "
            "Human review is required before the node can resume operations."
        )
    else:
        s4 = "The node has been placed on hold pending human review."

    return f"{s1} {s2} {s3} {s4}"


def _confidence_level(event_count: int, correlations: list, top_threats: list) -> str:
    score = 0
    if event_count >= 5:
        score += 2
    elif event_count >= 2:
        score += 1
    if correlations:
        score += 3 if any(c["multiplier"] >= 2.5 for c in correlations) else 2
    if top_threats and SEVERITY_ORDER.get(top_threats[0].get("severity", ""), 0) >= 3:
        score += 1
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


# ── Public API ────────────────────────────────────────────────────────────────

def build_incident_summary(
    node: str,
    node_status: dict,
    events: list[dict],
    alerts: list[dict],
    forensic: dict | None,
) -> dict:
    """
    Build a structured incident summary for the Human Review panel.

    Args:
        node:        Node name (e.g. "node2")
        node_status: Row from node_status table
        events:      Recent scored events from the events table (ordered newest-first)
        alerts:      Recent security_alerts for this node
        forensic:    Latest forensic_snapshot row (or None)

    Returns:
        A dict ready for JSON serialisation and frontend consumption.
    """

    risk_score = float(node_status.get("risk_score", 0))
    paused_at  = node_status.get("last_updated", "")

    # ── Collect threat types ─────────────────────────────────────────
    threat_type_counts: dict[str, dict] = {}
    for alert in alerts:
        tt  = alert.get("threat_type", "UNKNOWN")
        sev = alert.get("severity", "INFO")
        if tt not in threat_type_counts:
            threat_type_counts[tt] = {"threat_type": tt, "count": 0, "severity": sev}
        threat_type_counts[tt]["count"] += 1
        # Keep highest severity seen
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(threat_type_counts[tt]["severity"], 0):
            threat_type_counts[tt]["severity"] = sev

    top_threats = sorted(
        threat_type_counts.values(),
        key=lambda x: (SEVERITY_ORDER.get(x["severity"], 0), x["count"]),
        reverse=True,
    )[:5]

    # ── Observed threat type set for correlation check ───────────────
    observed_types = set(threat_type_counts.keys())
    for ev in events:
        reasons = _parse_json_field(ev.get("reasons"), [])
        for r in reasons:
            # Reasons are strings like "CONTAINER_EXEC", extract them
            for known in MITRE_MAP:
                if known in r:
                    observed_types.add(known)

    # ── Correlations ─────────────────────────────────────────────────
    correlations = _detect_correlations(observed_types)

    # ── Build threat timeline ────────────────────────────────────────
    timeline_entries = []

    # From security alerts (most precise)
    for alert in sorted(alerts, key=lambda a: a.get("timestamp", ""))[:20]:
        tt  = alert.get("threat_type", "UNKNOWN")
        sev = alert.get("severity", "INFO")
        ts  = alert.get("timestamp", "")
        mitre = MITRE_MAP.get(tt, {})
        timeline_entries.append({
            "timestamp": ts,
            "display_time": _fmt_ts(ts),
            "ago": _ago(ts),
            "event_type": tt,
            "severity": sev,
            "description": alert.get("description", ""),
            "mitre_id": mitre.get("id", ""),
            "mitre_name": mitre.get("name", ""),
            "source": "security_alert",
        })

    # From scored events (fill gaps)
    for ev in sorted(events, key=lambda e: e.get("timestamp", ""))[:15]:
        bucket = ev.get("bucket", "silent")
        if bucket == "silent":
            continue
        ts = ev.get("timestamp", "")
        reasons = _parse_json_field(ev.get("reasons"), [])
        timeline_entries.append({
            "timestamp": ts,
            "display_time": _fmt_ts(ts),
            "ago": _ago(ts),
            "event_type": f"RISK_SCORED ({bucket.upper()})",
            "severity": "CRITICAL" if bucket == "quarantine" else "HIGH" if bucket == "human" else "MEDIUM",
            "description": f"Risk score {ev.get('risk_score', 0):.1f} — {', '.join(reasons[:3]) or 'No reasons'}",
            "mitre_id": "",
            "mitre_name": "",
            "source": "risk_event",
            "risk_score": ev.get("risk_score", 0),
            "correlated": bool(ev.get("correlated")),
        })

    # Sort by timestamp, deduplicate
    timeline_entries.sort(key=lambda e: e.get("timestamp", ""))

    # ── Risk trajectory (sparkline data) ────────────────────────────
    risk_trajectory = [
        {
            "timestamp": ev.get("timestamp", ""),
            "display_time": _fmt_ts(ev.get("timestamp", "")),
            "score": float(ev.get("risk_score", 0)),
        }
        for ev in reversed(events[:30])
        if ev.get("risk_score") is not None
    ]

    # ── Enforcement actions ──────────────────────────────────────────
    enforcement = []
    status = node_status.get("status", "")
    if status in ("awaiting_approval", "quarantined"):
        enforcement.append("paused the container")
    if node_status.get("isolated_ip"):
        enforcement.append("applied iptables network isolation")
    if forensic:
        enforcement.append("captured a pre-quarantine forensic snapshot")

    # ── NIST references ──────────────────────────────────────────────
    nist_set: set[str] = set()
    for tt in observed_types:
        nist_set.update(NIST_MAP.get(tt, []))
    nist_references = sorted(nist_set)[:6]

    # ── MITRE ATT&CK techniques ─────────────────────────────────────
    mitre_techniques = []
    seen_mitre = set()
    for tt in sorted(observed_types):
        m = MITRE_MAP.get(tt)
        if m and m["id"] not in seen_mitre:
            mitre_techniques.append({"id": m["id"], "name": m["name"], "triggered_by": tt})
            seen_mitre.add(m["id"])

    # ── Recommended action ───────────────────────────────────────────
    recommended_action = _determine_recommended_action(observed_types, risk_score, correlations)

    # ── Confidence level ─────────────────────────────────────────────
    confidence = _confidence_level(len(events), correlations, top_threats)

    # ── Forensic summary ────────────────────────────────────────────
    forensic_summary = None
    if forensic:
        processes    = _parse_json_field(forensic.get("processes"), [])
        net_conns    = _parse_json_field(forensic.get("network_conns"), [])
        cont_state   = _parse_json_field(forensic.get("container_state"), {})
        forensic_summary = {
            "captured_at":     forensic.get("captured_at", ""),
            "trigger":         forensic.get("trigger", ""),
            "process_count":   len([p for p in processes if not isinstance(p, dict) or "error" not in p]),
            "network_connections": len([n for n in net_conns if not isinstance(n, dict) or "error" not in n]),
            "container_image": cont_state.get("image", "unknown"),
            "container_pid":   cont_state.get("pid", ""),
            "artifact_path":   forensic.get("artifact_path", ""),
        }

    # ── Narrative ────────────────────────────────────────────────────
    narrative = _build_narrative(
        node=node,
        risk_score=risk_score,
        top_threats=top_threats,
        correlations=correlations,
        enforcement=enforcement,
        paused_at=paused_at,
        event_count=len(events),
    )

    return {
        "node":               node,
        "risk_score":         risk_score,
        "status":             status,
        "paused_at":          paused_at,
        "confidence_level":   confidence,
        "recommended_action": recommended_action,
        "narrative":          narrative,
        "top_threats":        top_threats,
        "timeline":           timeline_entries,
        "correlations":       correlations,
        "risk_trajectory":    risk_trajectory,
        "enforcement_actions": enforcement,
        "nist_references":    nist_references,
        "mitre_techniques":   mitre_techniques,
        "forensic_summary":   forensic_summary,
        "total_events":       len(events),
        "total_alerts":       len(alerts),
    }
