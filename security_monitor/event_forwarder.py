import os
import queue
import logging
import zmq

from secure_messenger import SecureMessenger

log = logging.getLogger("event_forwarder")
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "tcp://controller:5555")

class EventForwarder:
    def __init__(self, forward_queue):
        self.forward_queue = forward_queue
        
    def run(self):
        log.info("Event forwarder thread started.")
        
        ctx = zmq.Context()
        sender = ctx.socket(zmq.PUSH)
        sender.connect(CONTROLLER_URL)
        log.info(f"Connected to Controller at {CONTROLLER_URL}")
        
        # We sign as security-monitor
        messenger = SecureMessenger(node_name="security-monitor")
        
        while True:
            try:
                event = self.forward_queue.get()
            except Exception:
                continue
                
            # Construct synthetic security alert format that Controller/Risk Engine understands.
            # The risk engine's validate() requires the "node" key; the security_alert path
            # requires node_id for AlertManager. Both are populated from the same source value.
            node_name = event.get("node_id") or event.get("node") or "unknown"
            payload = {
                "security_alert": True,
                "node":      node_name,   # required by engine.validate() → "_offset" + "node"
                "node_id":   node_name,   # consumed by AlertManager.emit_from_event()
                "threat_type": event.get("threat_type"),
                "severity":    event.get("severity"),
                "description": event.get("description"),
                "evidence":    event.get("evidence", {}),
                "recommended_action": "Investigate immediately. Central policy engine evaluating fast-path enforcement.",
                # Basic telemetry defaults to pass risk engine validate()
                "cpu_usage":    0.0,
                "memory_usage": 0.0,
                "process_count": 0,
                "is_busy":       False,
                "active_job_type": None,
            }
            
            try:
                signed = messenger.sign(payload)
                sender.send_json(signed)
                log.info(f"Forwarded security event for {event.get('node_id')} to controller.")
            except Exception as e:
                log.error(f"Failed to forward security event: {e}")
