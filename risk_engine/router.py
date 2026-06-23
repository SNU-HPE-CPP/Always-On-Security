import logging
import os
import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from network_isolator import NetworkIsolator

log = logging.getLogger(__name__)

ALERT_INGESTOR_MANAGER_IP = "alert_ingestor"
ALERT_INGESTOR_PORT = (
    5514  # Wazuh mock listens on 5514 (non-root); real Wazuh uses 514 (root/privileged)
)

# Directory where forensic JSON artefacts are written (survives container restart)
FORENSICS_DIR = Path(os.getenv("FORENSICS_DIR", "/data/forensics"))


class Router:
    def __init__(self, store=None):
        self._docker = None
        # Store reference is optional — allows forensic data to be written to DB
        self._store = store

    @classmethod
    def from_yaml(cls, thresholds_path: str, store=None) -> "Router":
        return cls(store=store)

    def _get_docker(self):
        if self._docker is None:
            try:
                import docker

                self._docker = docker.from_env()
            except Exception as e:
                log.error(f"Docker client init failed: {e}")
        return self._docker

    def dispatch(self, decision) -> None:

        node = decision.node
        bucket = decision.bucket
        score = decision.cumulative_score
        corr_tag = " [CORRELATED]" if decision.correlated else ""
        rule_ids = [r[0] for r in decision.matched_rules]
        reasons = decision.raw_event.get("reasons", [])

        log.info(
            f"[{bucket.upper()}]{corr_tag} "
            f"node={node} "
            f"cumulative={score:.2f} "
            f"event={decision.event_score:.4f} "
            f"rules={rule_ids}"
        )

        if bucket == "silent":
            return

        elif bucket == "auto":
            log.warning(f"[AUTO-REMEDIATION] node={node} score={score:.2f}")
            self._send_alert_ingestor_alert(
                node=node,
                risk_score=score,
                reasons=reasons,
                rule_ids=rule_ids,
                correlated=decision.correlated,
                severity="WARNING",
            )

        elif bucket == "human":
            log.warning(f"[HUMAN_REVIEW] node={node} score={score:.2f}")
            self._pause(node)
            self._send_alert_ingestor_alert(
                node=node,
                risk_score=score,
                reasons=reasons,
                rule_ids=rule_ids,
                correlated=decision.correlated,
                severity="HIGH",
            )

        elif bucket == "quarantine":
            log.critical(f"[QUARANTINE] node={node} score={score:.2f}")

            # ── REC-09: Capture forensic evidence BEFORE stopping the container ──
            self._capture_forensics(
                node=node,
                risk_score=score,
                trigger="QUARANTINE",
                rule_ids=rule_ids,
                reasons=reasons,
            )

            self._quarantine(node)
            self._send_alert_ingestor_alert(
                node=node,
                risk_score=score,
                reasons=reasons,
                rule_ids=rule_ids,
                correlated=decision.correlated,
                severity="CRITICAL",
            )

    # ── Enforcement actions ───────────────────────────────────────────────────

    def _pause(self, node: str) -> None:
        client = self._get_docker()
        if client is None:
            log.error(f"Cannot isolate {node}: Docker unavailable")
            return
        try:
            container = client.containers.get(node)
            container.reload()

            if container.status != "paused":
                container.pause()
                log.warning(f"Node {node} paused via Docker SDK.")

            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            mgmt_network = networks.get("mgmt-net")
            if mgmt_network and mgmt_network.get("IPAddress"):
                container_ip = mgmt_network["IPAddress"]
            else:
                container_ip = next(
                    (
                        details.get("IPAddress")
                        for details in networks.values()
                        if details.get("IPAddress")
                    ),
                    None,
                )

            if not container_ip:
                log.error(f"Cannot isolate {node}: no container IP found")
                return

            drop_rule = ["iptables", "-C", "FORWARD", "-s", container_ip, "-j", "DROP"]
            insert_rule = [
                "iptables",
                "-I",
                "FORWARD",
                "-s",
                container_ip,
                "-j",
                "DROP",
            ]

            check_result = subprocess.run(drop_rule, capture_output=True, text=True)
            if check_result.returncode != 0:
                subprocess.run(insert_rule, check=True)

            log.warning(
                f"Node {node} isolated with iptables DROP rule "
                f"(container_ip={container_ip})"
            )

            if self._store:
                self._store.set_isolated_ip(node, container_ip)

        except Exception as e:
            log.error(f"Isolation failed for {node}: {e}")

    def _quarantine(self, node: str) -> None:
        client = self._get_docker()
        if client is None:
            log.error(f"Cannot quarantine {node}: Docker unavailable")
            return
        try:
            container = client.containers.get(node)
            container.reload()
            if container.status in {"exited", "dead", "removing"}:
                log.info(f"Node {node} is already stopped; skipping quarantine")
                return
            container.stop()
            log.critical(f"Node {node} quarantined (container stopped)")
        except Exception as e:
            log.error(f"Quarantine failed for {node}: {e}")

    # ── REC-09: Forensic capture ──────────────────────────────────────────────

    def _capture_forensics(
        self,
        node: str,
        risk_score: float,
        trigger: str,
        rule_ids: list,
        reasons: list,
    ) -> None:
        """
        Capture a forensic snapshot of the node immediately before quarantine.
        Evidence is written to:
          1. The forensic_snapshots SQLite table (queryable by the dashboard)
          2. A JSON artefact file under /data/forensics/ (survives DB reset)

        NIST SP 800-234: IR-4 (Incident Handling), IR-5 (Incident Monitoring)
        """
        log.critical(
            "[FORENSICS] Starting pre-quarantine capture | node=%s trigger=%s score=%.2f",
            node,
            trigger,
            risk_score,
        )

        processes = self._collect_processes(node)
        network_conns = self._collect_network(node)
        container_state = self._collect_container_state(node)
        recent_alerts = self._collect_recent_alerts(node)
        recent_events = self._collect_recent_events(node)

        artifact_path = self._write_forensic_artifact(
            node=node,
            trigger=trigger,
            risk_score=risk_score,
            rule_ids=rule_ids,
            reasons=reasons,
            processes=processes,
            network_conns=network_conns,
            container_state=container_state,
            recent_alerts=recent_alerts,
            recent_events=recent_events,
        )

        if self._store is not None:
            try:
                self._store.write_forensic_snapshot(
                    node=node,
                    trigger=trigger,
                    risk_score=risk_score,
                    processes=processes,
                    network_conns=network_conns,
                    container_state=container_state,
                    recent_alerts=recent_alerts,
                    recent_events=recent_events,
                    artifact_path=str(artifact_path) if artifact_path else None,
                )
            except Exception as exc:
                log.error("[FORENSICS] Failed to write snapshot to DB: %s", exc)

        log.critical(
            "[FORENSICS] Capture complete | node=%s artifact=%s",
            node,
            artifact_path,
        )

    def _collect_processes(self, node: str) -> list:
        """
        Collect running processes via Docker SDK top() — goes through the
        socket proxy, no bare subprocess docker exec.
        FIX #10: Replaced subprocess docker exec with container.top() SDK call.
        """
        client = self._get_docker()
        if client is None:
            return [{"error": "Docker client unavailable"}]
        try:
            container = client.containers.get(node)
            container.reload()
            result = container.top(ps_args="aux")
            titles = result.get("Titles", [])
            procs = result.get("Processes", []) or []
            lines = []
            for row in procs:
                entry = dict(zip(titles, row))
                lines.append(
                    {
                        "user": entry.get("USER", ""),
                        "pid": entry.get("PID", ""),
                        "cpu_pct": entry.get("%CPU", ""),
                        "mem_pct": entry.get("%MEM", ""),
                        "command": entry.get("COMMAND", ""),
                    }
                )
            return lines
        except Exception as exc:
            log.warning("[FORENSICS] Process collection failed for %s: %s", node, exc)
            return [{"error": str(exc)}]

    def _collect_network(self, node: str) -> list:
        """
        Collect network connections via Docker SDK exec_run() — goes through the
        socket proxy, no bare subprocess docker exec.
        FIX #10: Replaced subprocess docker exec with container.exec_run() SDK call.
        """
        client = self._get_docker()
        if client is None:
            return [{"error": "Docker client unavailable"}]
        try:
            container = client.containers.get(node)
            container.reload()
            # Try ss first, fall back to netstat
            for cmd in (["ss", "-tnp"], ["netstat", "-tnp"]):
                result = container.exec_run(cmd, demux=False)
                if result.exit_code == 0:
                    output = (
                        result.output.decode(errors="replace") if result.output else ""
                    )
                    lines = []
                    for line in output.strip().splitlines()[1:]:  # skip header
                        parts = line.split()
                        if len(parts) >= 5:
                            lines.append(
                                {
                                    "state": parts[0],
                                    "local_addr": parts[3] if len(parts) > 3 else "",
                                    "remote_addr": parts[4] if len(parts) > 4 else "",
                                    "process": parts[-1],
                                }
                            )
                    return lines
            return [{"error": "ss and netstat both unavailable in container"}]
        except Exception as exc:
            log.warning("[FORENSICS] Network collection failed for %s: %s", node, exc)
            return [{"error": str(exc)}]

    def _collect_container_state(self, node: str) -> dict:
        """Return container inspect attributes (state, image, mounts, env-safe)."""
        client = self._get_docker()
        if client is None:
            return {"error": "Docker client unavailable"}
        try:
            container = client.containers.get(node)
            container.reload()
            attrs = container.attrs
            return {
                "id": attrs.get("Id", "")[:12],
                "image": attrs.get("Config", {}).get("Image", ""),
                "status": attrs.get("State", {}).get("Status", ""),
                "started": attrs.get("State", {}).get("StartedAt", ""),
                "pid": attrs.get("State", {}).get("Pid", ""),
                "networks": {
                    net: {
                        "ip": info.get("IPAddress"),
                        "mac": info.get("MacAddress"),
                    }
                    for net, info in attrs.get("NetworkSettings", {})
                    .get("Networks", {})
                    .items()
                },
                "mounts": [
                    {
                        "type": m.get("Type"),
                        "source": m.get("Source"),
                        "dest": m.get("Destination"),
                        "mode": m.get("Mode"),
                    }
                    for m in attrs.get("Mounts", [])
                ],
            }
        except Exception as exc:
            log.warning(
                "[FORENSICS] Container state collection failed for %s: %s", node, exc
            )
            return {"error": str(exc)}

    def _collect_recent_alerts(self, node: str, limit: int = 20) -> list:
        """Pull the most recent security alerts for this node from the DB."""
        if self._store is None:
            return []
        try:
            return self._store.get_alerts(node_id=node, limit=limit)
        except Exception as exc:
            log.warning("[FORENSICS] Alert collection failed for %s: %s", node, exc)
            return [{"error": str(exc)}]

    def _collect_recent_events(self, node: str, limit: int = 20) -> list:
        """Pull the last N telemetry events for this node from the DB."""
        if self._store is None:
            return []
        try:
            rows = self._store.conn.execute(
                """
                SELECT timestamp, event_type, risk_score, bucket, reasons, matched_rules
                FROM events WHERE node = ?
                ORDER BY id DESC LIMIT ?
            """,
                (node, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            log.warning("[FORENSICS] Event collection failed for %s: %s", node, exc)
            return [{"error": str(exc)}]

    def _write_forensic_artifact(
        self,
        node: str,
        trigger: str,
        risk_score: float,
        rule_ids: list,
        reasons: list,
        processes: list,
        network_conns: list,
        container_state: dict,
        recent_alerts: list,
        recent_events: list,
    ) -> Path | None:
        """Write a self-contained JSON forensic artefact file to /data/forensics/."""
        try:
            FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
            ts_safe = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            artifact_path = FORENSICS_DIR / f"{node}_{trigger}_{ts_safe}.json"
            record = {
                "schema_version": "1.0",
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "node": node,
                "trigger": trigger,
                "risk_score": risk_score,
                "matched_rules": rule_ids,
                "reasons": reasons,
                "processes": processes,
                "network_connections": network_conns,
                "container_state": container_state,
                "recent_security_alerts": recent_alerts,
                "recent_telemetry_events": recent_events,
            }
            artifact_path.write_text(json.dumps(record, indent=2, default=str))
            log.critical("[FORENSICS] Artifact saved: %s", artifact_path)
            return artifact_path
        except Exception as exc:
            log.error("[FORENSICS] Failed to write artifact: %s", exc)
            return None

    # ── Wazuh SIEM integration ────────────────────────────────────────────────

    def _send_alert_ingestor_alert(
        self,
        node: str,
        risk_score: float,
        reasons: list,
        rule_ids: list,
        correlated: bool,
        severity: str = "CRITICAL",
    ) -> None:

        payload = {
            "source": "always-on-security",
            "severity": severity,
            "node": node,
            "risk_score": risk_score,
            "matched_rules": rule_ids,
            "correlated": correlated,
            "reasons": reasons,
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(
                json.dumps(payload).encode(),
                (ALERT_INGESTOR_MANAGER_IP, ALERT_INGESTOR_PORT),
            )
            sock.close()
            log.info(
                f"[ALERT_INGESTOR] Alert sent for {node} (Risk Score: {risk_score})"
            )
        except Exception as e:
            log.error(f"[ALERT_INGESTOR] Failed to send alert: {e}")
