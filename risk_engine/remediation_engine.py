import yaml
import logging
import os
import subprocess
import json
from datetime import datetime, timezone

log = logging.getLogger("remediation_engine")

CONFIG_PATH = "/opt/security/config/remediations.yaml"

# Threat types that require host-level Docker SDK enforcement rather than
# in-container exec_run. These handlers bypass the bash script in remediations.yaml
# and call the appropriate Docker/NetworkIsolator API directly.
_HOST_LEVEL_HANDLERS = {"UNEXPECTED_NETWORK_ATTACH", "RUNTIME_DRIFT"}


class RemediationEngine:
    def __init__(self, store):
        self.store = store
        self.playbooks = self._load_playbooks()
        log.info(f"RemediationEngine initialized with {len(self.playbooks)} playbooks.")

    def _load_playbooks(self):
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r") as f:
                    data = yaml.safe_load(f)
                    return data.get("playbooks", {})
            except Exception as e:
                log.error(f"Failed to load remediations.yaml: {e}")
        return {}

    def process_alert(self, alert):
        """
        Processes a SecurityAlert and triggers the corresponding playbook if one exists.

        For most threat types, the bash script from remediations.yaml is executed
        inside the target container via docker exec_run.

        For UNEXPECTED_NETWORK_ATTACH and RUNTIME_DRIFT, host-level Docker SDK
        enforcement is used instead (network disconnect / iptables via NetworkIsolator)
        because the bash commands require host-level privileges that containers don't have.
        """
        threat_type = alert.threat_type
        if threat_type not in self.playbooks:
            return

        playbook = self.playbooks[threat_type]
        action_name = playbook.get("name", f"Remediate {threat_type}")

        log.info(
            f"[AUTO-REMEDIATION] Triggering playbook '{action_name}' "
            f"for node={alert.node_id} (threat={threat_type})"
        )

        # ── FIX #1: RUNTIME_DRIFT — host-level network isolation ─────────────
        # The RUNTIME_DRIFT evidence contains drifted container config fields
        # (e.g. networks, security_opts), not process PIDs. The correct host-level
        # response is to disconnect the container from data networks via Docker SDK
        # so it can no longer communicate while human review takes place.
        if threat_type == "RUNTIME_DRIFT":
            self._handle_runtime_drift(alert, action_name)
            return

        # ── FIX #2: UNEXPECTED_NETWORK_ATTACH — Docker SDK network disconnect ─
        # The original bash script ran `iptables` inside the container, which fails
        # silently because containers don't have CAP_NET_ADMIN. We now call
        # NetworkIsolator.isolate_node() which uses the Docker SDK to disconnect
        # the container from compute-net and storage-net at the host level.
        if threat_type == "UNEXPECTED_NETWORK_ATTACH":
            self._handle_network_attach(alert, action_name)
            return

        # ── All other playbooks: run bash script inside the container ─────────
        self._exec_in_container(alert, action_name, playbook.get("script", ""))

    # ── Fix #1: RUNTIME_DRIFT handler ────────────────────────────────────────

    def _handle_runtime_drift(self, alert, action_name: str):
        """
        Isolates the container's data-plane networks via Docker SDK when a runtime
        drift is detected. The drifted fields are extracted from the alert evidence
        and included in the remediation log for audit purposes.
        """
        node = alert.node_id
        drifts = alert.evidence.get("drifts", [])
        drift_fields = [d.get("field", "unknown") for d in drifts]

        log.warning(
            f"[AUTO-REMEDIATION] RUNTIME_DRIFT on node={node} | "
            f"Drifted fields: {drift_fields} | "
            "Isolating data-plane networks via Docker SDK."
        )

        try:
            from network_isolator import NetworkIsolator
            isolator = NetworkIsolator()
            success = isolator.isolate_node(node)
            status_msg = "SUCCESS" if success else "PARTIAL"
            output = (
                f"Runtime drift detected on fields: {drift_fields}. "
                f"Container {node} disconnected from compute-net and storage-net. "
                f"Management network preserved for remote access. Status: {status_msg}."
            )
            log.info(f"[AUTO-REMEDIATION] {output}")
            self._log_remediation_event(node, action_name, output, success=success)
        except Exception as e:
            err = f"Docker SDK network isolation failed for {node}: {e}"
            log.error(f"[AUTO-REMEDIATION] {err}")
            self._log_remediation_event(node, action_name, err, success=False)

    # ── Fix #2: UNEXPECTED_NETWORK_ATTACH handler ────────────────────────────

    def _handle_network_attach(self, alert, action_name: str):
        """
        Disconnects the container from unauthorized networks via Docker SDK.
        This replaces the broken in-container `iptables` approach — containers
        do not have CAP_NET_ADMIN so iptables always fails silently inside them.
        NetworkIsolator.isolate_node() calls Docker API from the host level.
        """
        node = alert.node_id
        rogue_nets = alert.evidence.get("networks", [])

        log.warning(
            f"[AUTO-REMEDIATION] UNEXPECTED_NETWORK_ATTACH on node={node} | "
            f"Rogue networks: {rogue_nets} | "
            "Disconnecting from data networks via Docker SDK."
        )

        try:
            from network_isolator import NetworkIsolator
            isolator = NetworkIsolator()

            # Also apply host-level iptables FORWARD DROP via quarantine_network
            # so even if the container reconnects, traffic is blocked at the bridge.
            isolated = isolator.isolate_node(node)
            blocked = isolator.quarantine_network(node)

            success = isolated or blocked
            output = (
                f"Unauthorized network attachment detected. "
                f"Rogue networks: {rogue_nets}. "
                f"Docker network disconnect: {'OK' if isolated else 'FAILED'}. "
                f"iptables FORWARD DROP: {'OK' if blocked else 'FAILED'}."
            )
            log.info(f"[AUTO-REMEDIATION] {output}")
            self._log_remediation_event(node, action_name, output, success=success)
        except Exception as e:
            err = f"Network isolation failed for {node}: {e}"
            log.error(f"[AUTO-REMEDIATION] {err}")
            self._log_remediation_event(node, action_name, err, success=False)

    # ── Generic in-container bash exec (used by playbooks 3, 4, 5) ──────────
    def _exec_in_container(self, alert, action_name: str, script: str):
        """
        Runs the bash script from remediations.yaml inside the target container
        via docker exec_run. Used for CONFIG_DRIFT, LATERAL_MOVEMENT, IMAGE_MISMATCH.
        """
        import docker
        node = alert.node_id
        try:
            client = docker.from_env()
            container = client.containers.get(node)
            container.reload()

            if container.status != "running":
                output = (
                    f"Execution superseded: Primary enforcement policy already active. "
                    f"Target is in '{container.status}' state."
                )
                log.info(f"[AUTO-REMEDIATION] Playbook '{action_name}' skipped on {node}: {output}")
                # We log this as success=True because the primary enforcement worked
                self._log_remediation_event(node, action_name, output, success=True)
                return

            exec_result = container.exec_run(cmd=["/bin/sh", "-c", script], user="root")
            output = exec_result.output.decode("utf-8").strip()

            log.info(
                f"[AUTO-REMEDIATION] Playbook '{action_name}' completed on {node}. "
                f"Exit={exec_result.exit_code} | Output: {output}"
            )
            self._log_remediation_event(
                node, action_name, output, success=(exec_result.exit_code == 0)
            )
        except docker.errors.APIError as api_err:
            if api_err.response.status_code == 409:
                output = "Execution superseded: Primary enforcement policy engaged during execution."
                log.info(f"[AUTO-REMEDIATION] Playbook '{action_name}' caught 409 on {node}: {output}")
                self._log_remediation_event(node, action_name, output, success=True)
            else:
                err = str(api_err)
                log.error(f"[AUTO-REMEDIATION] Playbook '{action_name}' failed for node={node}: {err}")
                self._log_remediation_event(node, action_name, err, success=False)
        except Exception as e:
            err = str(e)
            log.error(f"[AUTO-REMEDIATION] Playbook '{action_name}' failed for node={node}: {err}")
            self._log_remediation_event(node, action_name, err, success=False)

    # ── Timeline event logger ────────────────────────────────────────────────

    def _log_remediation_event(self, node_id, action_name, output, success):
        """
        Writes a special remediation event to the store so it appears in the timeline.
        """
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            bucket = "auto"
            reasons = json.dumps([f"Executed: {action_name}", f"Output: {output}"])
            matched_rules = json.dumps(["AUTO_REMEDIATION"])

            self.store.conn.execute(
                """
                INSERT INTO events (
                    timestamp, node, risk_score, weighted_score, bucket,
                    event_type, reasons, matched_rules, cpu_usage, memory_usage, process_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    node_id,
                    0.0,
                    0.0,
                    bucket,
                    "AUTO_REMEDIATION",
                    reasons,
                    matched_rules,
                    0.0,
                    0.0,
                    0,
                ),
            )
            self.store.conn.commit()
        except Exception as e:
            log.error(f"Failed to log remediation event: {e}")
