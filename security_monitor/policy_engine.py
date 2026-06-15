import os
import yaml
import logging
import docker

log = logging.getLogger("policy_engine")
AUDIT_LOG = "/var/log/security/audit.log"
CONFIG_PATH = "/opt/security/config/fast_path_policy.yaml"

class PolicyEngine:
    def __init__(self, input_queue, output_queue):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.docker_client = None
        self.policies = self._load_policies()

    def _get_docker(self):
        if not self.docker_client:
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                log.error(f"Failed to connect to Docker SDK: {e}")
        return self.docker_client

    def _load_policies(self) -> list:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH) as f:
                    data = yaml.safe_load(f) or {}
                    return data.get("policies", [])
            except Exception as e:
                log.error(f"Failed to load fast path policy: {e}")
        
        # Default fallback policies
        return [
            {"threat_type": "ROGUE_NODE", "action": "quarantine"},
            {"threat_type": "NODE_IMPERSONATION", "action": "quarantine"},
            {"threat_type": "CONFIG_TAMPER", "action": "quarantine"},
            {"severity": "CRITICAL", "action": "quarantine"},
            {"threat_type": "Lateral_Movement", "action": "pause"},
            {"threat_type": "Fanout_Excess", "action": "network_isolate"}
        ]

    def _audit_log(self, node_id: str, threat_type: str, action: str, success: bool, error_msg: str = ""):
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        status = "SUCCESS" if success else f"FAILED: {error_msg}"
        msg = f"Audit: node={node_id} threat={threat_type} action={action} status={status}\n"
        with open(AUDIT_LOG, "a") as f:
            f.write(msg)
        log.warning(msg.strip())

    def _apply_action(self, node_id: str, action: str, threat_type: str):
        client = self._get_docker()
        if not client:
            log.error("Docker client unavailable. Skipping action.")
            return

        if node_id in ["security-monitor", "unknown"]:
            return

        try:
            container = client.containers.get(node_id)
            
            if action == "quarantine":
                log.critical(f"[FAST-PATH POLICY] Stopping compromised container {node_id}")
                container.stop()
                self._audit_log(node_id, threat_type, "stop", True)
                
            elif action == "pause":
                log.critical(f"[FAST-PATH POLICY] Pausing compromised container {node_id}")
                container.pause()
                self._audit_log(node_id, threat_type, "pause", True)
                
            elif action == "network_isolate":
                log.critical(f"[FAST-PATH POLICY] Disconnecting compromised container {node_id} from data networks")
                for net_name in ["compute-net", "storage-net"]:
                    try:
                        net = client.networks.get(net_name)
                        net.disconnect(container)
                    except Exception as disconnect_err:
                        log.debug(f"Disconnect from {net_name} failed/skipped: {disconnect_err}")
                self._audit_log(node_id, threat_type, "network_isolate", True)
                
        except Exception as e:
            log.error(f"Failed to execute fast-path action '{action}' on {node_id}: {e}")
            self._audit_log(node_id, threat_type, action, False, str(e))

    def run(self):
        log.info("Policy engine thread started.")
        while True:
            try:
                event = self.input_queue.get()
            except Exception:
                continue

            node_id = event.get("node_id", "unknown")
            threat_type = event.get("threat_type", "UNKNOWN")
            severity = event.get("severity", "MEDIUM")

            # Evaluate policy
            action_to_take = None
            for p in self.policies:
                match = True
                if "threat_type" in p and p["threat_type"] != threat_type:
                    match = False
                if "severity" in p and p["severity"] != severity:
                    match = False
                
                if match:
                    action_to_take = p.get("action")
                    break

            if action_to_take:
                self._apply_action(node_id, action_to_take, threat_type)

            # Pass along to event forwarder
            self.output_queue.put(event)
