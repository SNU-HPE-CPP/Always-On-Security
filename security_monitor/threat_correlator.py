import time
import queue
import logging
import docker
from collections import deque

log = logging.getLogger("threat_correlator")

CORRELATION_WINDOW = 10.0  # seconds


class ThreatCorrelator:
    def __init__(self, input_queue, output_queue):
        self.input_queue = input_queue
        self.output_queue = output_queue
        # Store recent Docker events: node -> deque of (timestamp, event_dict)
        self.docker_history = {}
        # Keep IP to Node Name map cached
        self.ip_to_node = {}
        self.last_map_update = 0.0
        
    def _update_ip_map(self):
        now = time.time()
        if now - self.last_map_update < 5.0:
            return
            
        try:
            client = docker.from_env()
            new_map = {}
            for container in client.containers.list():
                name = container.name
                if name in ["node1", "node2", "node3", "node4"]:
                    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
                    for net_name, net_detail in networks.items():
                        ip = net_detail.get("IPAddress")
                        if ip:
                            new_map[ip] = name
            self.ip_to_node = new_map
            self.last_map_update = now
        except Exception as e:
            log.error(f"Failed to update IP to Node map: {e}")

    def resolve_node(self, ip_or_name) -> str:
        self._update_ip_map()
        if not ip_or_name:
            return "unknown"
            
        # Already a node name
        if ip_or_name in ["node1", "node2", "node3", "node4"]:
            return ip_or_name
            
        return self.ip_to_node.get(ip_or_name, "unknown")

    def run(self):
        log.info("Threat correlator thread started.")
        while True:
            try:
                event = self.input_queue.get(timeout=1.0)
            except queue.Empty:
                continue
                
            now = time.time()
            source = event.get("source")
            
            if source == "docker":
                node = event.get("node")
                if node not in self.docker_history:
                    self.docker_history[node] = deque()

                # Evict old events
                dq = self.docker_history[node]
                while dq and now - dq[0][0] > CORRELATION_WINDOW:
                    dq.popleft()

                dq.append((now, event))
                log.debug(f"Cached Docker event for {node}: {event.get('action')}")

                # Forward docker events that carry an explicit threat_type immediately
                # without waiting for a network event to trigger correlation.
                threat = event.get("threat_type")
                if threat in ("CONTAINER_EXEC", "UNEXPECTED_EXEC",
                              "SUSPICIOUS_RESTART_PATTERN", "UNEXPECTED_NETWORK_ATTACH",
                              "CONTAINER_RENAME"):
                    self.output_queue.put({
                        "node_id":     node,
                        "threat_type": threat,
                        "severity":    "HIGH",
                        "description": f"Docker behavioural threat detected: {threat} on {node}",
                        "correlated":  0,
                        "evidence":    {"docker_event": event},
                    })
                    log.warning(f"[DIRECT] {threat} on {node} forwarded to pipeline")
                
            elif source in ["suricata", "zeek", "falco"]:
                # Try to map IP or container name to node name
                src  = event.get("src_ip", "") or event.get("node_id", "")
                dst  = event.get("dest_ip", "")

                # Falco already provides node_id as container name
                if source == "falco":
                    node = event.get("node_id", "unknown")
                    if node not in ["node1", "node2", "node3", "node4", "security-monitor"]:
                        node = self.resolve_node(src) if src else "unknown"
                else:
                    node = self.resolve_node(src)
                    if node == "unknown":
                        node = self.resolve_node(dst)

                if node == "unknown":
                    log.warning(f"Could not map IP {src} -> {dst} to any tenant node.")
                    node = "security-monitor"
                    
                # Look for matching Docker events in the window
                correlated = False
                correlation_evidence = []
                
                if node in self.docker_history:
                    dq = self.docker_history[node]
                    # Evict old
                    while dq and now - dq[0][0] > CORRELATION_WINDOW:
                        dq.popleft()
                        
                    if dq:
                        correlated = True
                        for _, d_evt in dq:
                            correlation_evidence.append(d_evt)
                            
                # Build unified correlated security event
                out_event = {
                    "node_id": node,
                    "threat_type": event.get("threat_type", "NETWORK_THREAT"),
                    "severity": event.get("severity", "MEDIUM"),
                    "description": event.get("description", ""),
                    "correlated": 1 if correlated else 0,
                    "evidence": {
                        "network_alert": event,
                        "docker_events": correlation_evidence if correlated else []
                    }
                }
                
                if correlated:
                    out_event["severity"] = "CRITICAL"  # Escalate if correlated
                    out_event["description"] = f"Correlated activity: {out_event['description']} combined with Docker event(s)"
                    log.warning(f"[CORRELATION] Correlated threat on {node}! Network alert + Docker events.")
                    
                self.output_queue.put(out_event)
