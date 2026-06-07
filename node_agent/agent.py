"""
Always-On Security — Node Agent  (Enhanced)
Dual-threaded agent + security collector:
  1. Telemetry Monitor  — hardware metrics, rule-based anomaly detection
  2. Job Worker         — receives job assignments, context-aware detection
  3. Security Collector — config tampering, lateral movement, process policy

All ZMQ messages are signed with HMAC-SHA256 via SecureMessenger.
"""

import zmq
import time
import os
import socket
import threading
import random
import psutil

from secure_messenger import SecureMessenger
from security_collector import SecurityCollector

# ----------------------------------
# IDENTITY
# ----------------------------------

NODE_NAME = os.getenv("NODE_NAME", socket.gethostname())

# ----------------------------------
# ZMQ CONTEXT (shared)
# ----------------------------------

context = zmq.Context()

# ----------------------------------
# SECURE MESSENGER (shared)
# ----------------------------------
# One instance — thread-safe seq counter

messenger = SecureMessenger(NODE_NAME)

# ----------------------------------
# SECURITY COLLECTOR (shared)
# ----------------------------------

security_collector = SecurityCollector()

# ----------------------------------
# SUSPICIOUS PROCESS LIST (legacy denylist — kept for backward compat)
# Process policy is now driven by security_collector / process_policy.yaml
# ----------------------------------

SUSPICIOUS_PROCESSES = [
    "nmap", "hydra", "nc", "netcat", "stress", "stress-ng",
    "hashcat", "john", "sqlmap", "metasploit",
]

# ----------------------------------
# CURRENT JOB TRACKING
# ----------------------------------

current_job = {
    "active": False,
    "job_type": None,
    "job_id": None,
}
job_lock = threading.Lock()

# ==================================
# THREAD 1: JOB WORKER (STUB)
# ==================================

def job_worker():
    """
    Receives jobs from the risk-engine/scheduler on port 5556,
    simulates execution, marks the node as busy/idle.
    """
    receiver = context.socket(zmq.PULL)
    receiver.bind("tcp://*:5556")
    print(f"[{NODE_NAME}] Job worker ready on :5556")

    while True:
        try:
            job = receiver.recv_json()
            job_id   = job.get("job_id", "unknown")
            job_type = job.get("job_type", "unknown")
            duration = job.get("duration", 5)

            print(f"[{NODE_NAME}] Executing job {job_id} (type={job_type}, duration={duration}s)")

            with job_lock:
                current_job["active"]   = True
                current_job["job_type"] = job_type
                current_job["job_id"]   = job_id

            time.sleep(duration)

            with job_lock:
                current_job["active"]   = False
                current_job["job_type"] = None
                current_job["job_id"]   = None

            print(f"[{NODE_NAME}] Completed job {job_id}")

        except Exception as e:
            print(f"[{NODE_NAME}] Job worker error: {e}")


# ==================================
# THREAD 2: TELEMETRY & ANOMALY
# ==================================

def telemetry_monitor():
    """
    Collects system metrics every 5 seconds, runs rule-based anomaly detection,
    merges security collector snapshot, and sends signed telemetry to controller.
    """
    sender = context.socket(zmq.PUSH)
    sender.connect("tcp://controller:5555")
    print(f"[{NODE_NAME}] Telemetry monitor started -> controller:5555")

    under_attack  = False
    attack_stage  = 0

    while True:
        # ---- Collect hardware telemetry ----
        cpu            = psutil.cpu_percent(interval=1)
        memory         = psutil.virtual_memory().percent
        process_count  = len(psutil.pids())

        # ---- Threat Simulator (demo) ----
        trigger_chance = 0.08 if NODE_NAME == "node1" else 0.03
        if not under_attack:
            if random.random() < trigger_chance:
                under_attack = True
                attack_stage = 1
                print(f"[{NODE_NAME}] [SIMULATOR] Threat simulation INITIATED!")
        else:
            attack_stage = min(4, attack_stage + 1)
            print(f"[{NODE_NAME}] [SIMULATOR] Escalating (Stage {attack_stage})")

        if under_attack:
            if attack_stage >= 1: cpu           = 92.5
            if attack_stage >= 2: memory        = 88.0
            if attack_stage >= 3: process_count = 310

        # ---- Anomaly detection state ----
        event_type = "NORMAL"
        reasons    = []

        with job_lock:
            is_busy         = current_job["active"]
            active_job_type = current_job["job_type"]

        # Rule 1: High CPU
        if cpu > 80:
            if not (is_busy and active_job_type == "cpu"):
                event_type = "SUSPICIOUS_ACTIVITY"
                reasons.append(f"High CPU usage detected: {cpu}%")

        # Rule 2: High Memory
        if memory > 85:
            if not (is_busy and active_job_type == "memory_access"):
                event_type = "SUSPICIOUS_ACTIVITY"
                reasons.append(f"High memory usage detected: {memory}%")

        # Rule 3: Too many processes
        if process_count > 300:
            event_type = "SUSPICIOUS_ACTIVITY"
            reasons.append(f"Too many running processes: {process_count}")

        # Rule 4: Suspicious processes (legacy — still checked for backward compat)
        detected_suspicious = []
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"]
                if pname and pname.lower() in SUSPICIOUS_PROCESSES:
                    detected_suspicious.append(pname)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if under_attack and attack_stage >= 4:
            detected_suspicious.append("hydra")

        for pname in detected_suspicious:
            event_type = "SUSPICIOUS_ACTIVITY"
            reasons.append(f"Suspicious process detected: {pname}")

        # ---- Merge security collector snapshot ----
        sec = security_collector.get_snapshot()

        if sec.get("config_tamper"):
            event_type = "SUSPICIOUS_ACTIVITY"
            for tf in sec.get("tampered_files", []):
                reasons.append(f"Config tamper: {tf['file']}")

        if sec.get("ssh_connections", 0) > 0:
            event_type = "SUSPICIOUS_ACTIVITY"
            reasons.append(
                f"Lateral movement: {sec['ssh_connections']} SSH connections "
                f"to peers {sec.get('lateral_peers', [])}"
            )

        if sec.get("unauthorized_procs"):
            event_type = "SUSPICIOUS_ACTIVITY"
            for p in sec["unauthorized_procs"]:
                reasons.append(f"Unauthorized process: {p['name']} (pid={p['pid']})")

        # ---- Build raw event payload ----
        raw_payload = {
            "node":               NODE_NAME,
            "cpu_usage":          cpu,
            "memory_usage":       memory,
            "process_count":      process_count,
            "event_type":         event_type,
            "reasons":            reasons,
            "is_busy":            is_busy,
            "active_job_type":    active_job_type,
            # Security collector fields
            "config_tamper":      sec.get("config_tamper", False),
            "tampered_files":     sec.get("tampered_files", []),
            "ssh_connections":    sec.get("ssh_connections", 0),
            "lateral_peers":      sec.get("lateral_peers", []),
            "peer_contact_count": sec.get("peer_contact_count", 0),
            "unauthorized_procs": sec.get("unauthorized_procs", []),
        }

        # ---- Sign and send ----
        signed_msg = messenger.sign(raw_payload)
        sender.send_json(signed_msg)

        if event_type != "NORMAL":
            print(f"[{NODE_NAME}] ALERT: {reasons}")

        time.sleep(5)


# ==================================
# THREAD 3: SECURITY COLLECTOR
# ==================================

def security_collector_thread():
    """Runs the SecurityCollector's main loop in a background thread."""
    security_collector.run()


# ==================================
# MAIN
# ==================================

print(f"[{NODE_NAME}] Starting enhanced agent (hardware + security telemetry)...")

t1 = threading.Thread(target=job_worker,              daemon=True, name="JobWorker")
t2 = threading.Thread(target=telemetry_monitor,       daemon=True, name="TelemetryMonitor")
t3 = threading.Thread(target=security_collector_thread, daemon=True, name="SecurityCollector")

t1.start()
t2.start()
t3.start()

print(f"[{NODE_NAME}] Agent running (job worker + telemetry + security collector)")

while True:
    time.sleep(1)
