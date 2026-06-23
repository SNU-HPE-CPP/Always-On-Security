"""
security_monitor/docker_collector.py — Docker Event Security Analytics

Improvement 4: Expanded Docker event collection.

Monitored event types (beyond basic lifecycle):
  exec_create / exec_start / exec_die  → CONTAINER_EXEC / UNEXPECTED_EXEC
  rename                               → container identity change
  image pull / image delete            → image provenance events
  network connect / disconnect         → UNEXPECTED_NETWORK_ATTACH
  restart loops                        → SUSPICIOUS_RESTART_PATTERN

All detection occurs from outside containers — no exec into workloads.
"""

from __future__ import annotations

import time
import logging
from collections import defaultdict, deque

import docker

log = logging.getLogger("docker_collector")

# Nodes whose events are security-relevant
MONITORED_NODES = {"node1", "node2", "node3", "node4"}
# These actions are expected during normal operations
NORMAL_ACTIONS  = {"start", "die", "stop", "kill", "create", "destroy", "attach", "detach"}

# Restart loop detection: N restarts within WINDOW seconds = suspicious
RESTART_LOOP_THRESHOLD = 5
RESTART_LOOP_WINDOW    = 120  # seconds


def run_docker_collector(event_queue):
    log.info("Docker collector thread started.")
    # Per-node restart timestamps for loop detection
    restart_times: dict[str, deque] = defaultdict(deque)

    while True:
        try:
            client = docker.from_env()
            for event in client.events(decode=True):
                evt_type   = event.get("Type", "")
                action     = event.get("Action", "").split(":")[0]  # strip exec ID suffix
                actor      = event.get("Actor", {})
                attrs      = actor.get("Attributes", {})
                name       = attrs.get("name", "")
                ts         = event.get("time", time.time())
                image      = attrs.get("image", "")
                event_id   = event.get("id", "")

                # ── Container events ─────────────────────────────────────
                if evt_type == "container":
                    if name not in MONITORED_NODES:
                        continue

                    base_evt = {
                        "source":    "docker",
                        "node":      name,
                        "action":    action,
                        "timestamp": ts,
                        "status":    event.get("status"),
                        "id":        event_id,
                        "image":     image,
                        "exit_code": attrs.get("exitCode", ""),
                    }

                    # Restart loop detection
                    if action in ("start", "restart"):
                        dq = restart_times[name]
                        now = time.time()
                        cutoff = now - RESTART_LOOP_WINDOW
                        while dq and dq[0] < cutoff:
                            dq.popleft()
                        dq.append(now)
                        if len(dq) >= RESTART_LOOP_THRESHOLD:
                            log.warning(
                                f"[SUSPICIOUS_RESTART_PATTERN] node={name} "
                                f"restarts={len(dq)} in {RESTART_LOOP_WINDOW}s"
                            )
                            base_evt["threat_type"] = "SUSPICIOUS_RESTART_PATTERN"
                            base_evt["restart_count"] = len(dq)
                            base_evt["window_seconds"] = RESTART_LOOP_WINDOW

                    # exec events — operator executed something inside container
                    elif action in ("exec_create", "exec_start", "exec_die"):
                        if action != "exec_start":
                            continue
                        exec_cmd = attrs.get("execID", "") or attrs.get("exec_cmd", "")
                        log.warning(
                            f"[CONTAINER_EXEC] node={name} action={action} "
                            f"exec_id={exec_cmd}"
                        )
                        base_evt["threat_type"] = "UNEXPECTED_EXEC"
                        base_evt["exec_id"] = exec_cmd

                    # rename — container identity manipulation
                    elif action == "rename":
                        old_name = attrs.get("oldName", "")
                        log.warning(f"[RENAME] node={name} renamed from {old_name}")
                        base_evt["threat_type"] = "CONTAINER_RENAME"
                        base_evt["old_name"] = old_name

                    log.info(f"Container event: node={name} action={action}")
                    event_queue.put(base_evt)

                # ── Image events ─────────────────────────────────────────
                elif evt_type == "image":
                    if action in ("pull", "delete", "untag"):
                        log.info(f"Image event: action={action} image={image or event_id}")
                        event_queue.put({
                            "source":     "docker",
                            "node":       "host-observer",
                            "action":     action,
                            "timestamp":  ts,
                            "event_type": "IMAGE_EVENT",
                            "image":      image or event_id,
                            "threat_type": "IMAGE_PULL" if action == "pull" else "IMAGE_DELETE",
                        })

                # ── Network events ───────────────────────────────────────
                elif evt_type == "network":
                    container_name = attrs.get("container", "")
                    network_name   = attrs.get("name", "")
                    if container_name in MONITORED_NODES:
                        if action in ("connect", "disconnect"):
                            if action != "connect":
                                continue
                            log.warning(
                                f"[NETWORK_{action.upper()}] "
                                f"container={container_name} network={network_name}"
                            )
                            event_queue.put({
                                "source":       "docker",
                                "node":         container_name,
                                "action":       action,
                                "timestamp":    ts,
                                "threat_type":  "UNEXPECTED_NETWORK_ATTACH",
                                "network_name": network_name,
                            })

        except Exception as e:
            log.error(f"Error in Docker event listener: {e}")
            time.sleep(5)
