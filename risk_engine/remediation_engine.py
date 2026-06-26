import yaml
import logging
import os
import subprocess
import json

log = logging.getLogger("remediation_engine")

CONFIG_PATH = "/opt/security/config/remediations.yaml"

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
        """
        threat_type = alert.threat_type
        if threat_type not in self.playbooks:
            return

        playbook = self.playbooks[threat_type]
        action_name = playbook.get("name", f"Remediate {threat_type}")
        script = playbook.get("script", "")

        log.info(f"[AUTO-REMEDIATION] Triggering playbook '{action_name}' for node={alert.node_id} (threat={threat_type})")

        # Execute script via docker exec on the host, or using docker SDK
        # Because risk-engine has access to docker socket (if mounted) or we can use docker client
        import docker
        try:
            client = docker.from_env()
            container = client.containers.get(alert.node_id)
            
            # Run the bash script inside the container
            exec_result = container.exec_run(cmd=["/bin/sh", "-c", script], user="root")
            output = exec_result.output.decode('utf-8').strip()
            
            log.info(f"[AUTO-REMEDIATION] Playbook '{action_name}' completed on {alert.node_id}. Output: {output}")

            # Create an event record to show up in the timeline
            self._log_remediation_event(alert.node_id, action_name, output, success=(exec_result.exit_code == 0))

        except Exception as e:
            log.error(f"[AUTO-REMEDIATION] Playbook '{action_name}' failed for node={alert.node_id}: {e}")
            self._log_remediation_event(alert.node_id, action_name, str(e), success=False)

    def _log_remediation_event(self, node_id, action_name, output, success):
        """
        Writes a special remediation event to the store so it appears in the timeline.
        """
        try:
            event = {
                "node": node_id,
                "event_type": "AUTO_REMEDIATION",
                "reasons": [f"Executed: {action_name}"],
                "matched_rules": ["AUTO_REMEDIATION"],
                "evidence": {
                    "output": output,
                    "status": "SUCCESS" if success else "FAILED"
                },
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "process_count": 0
            }
            
            # Using store.write_event directly with a synthetic decision
            # To avoid creating circular dependencies, we just write it directly using SQL
            timestamp = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
            
            # We want this event to be visible, so we assign a bucket
            bucket = "auto"
            
            # Map "threat_type", "severity", and "evidence" into the JSON fields we have: "reasons" and "matched_rules"
            # so the DB doesn't crash on non-existent columns.
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
                    json.dumps(event["reasons"] + [f"Output: {output}"]),
                    json.dumps(event["matched_rules"]),
                    event["cpu_usage"],
                    event["memory_usage"],
                    event["process_count"]
                )
            )
            self.store.conn.commit()
            
        except Exception as e:
            log.error(f"Failed to log remediation event: {e}")
