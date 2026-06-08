"""
Always-On Security — Node Agent
Dual-threaded agent:
  1. Telemetry Monitor — collects system metrics, detects anomalies, sends security events
  2. Job Worker — receives job assignments, marks node as busy/idle for context-aware detection

Includes:
  - CPU anomaly simulation
  - Memory anomaly simulation
  - Process explosion simulation
  - Suspicious process simulation
  - Failed login burst simulation
  - Privilege escalation simulation
"""

import zmq
import time
import os
import socket
import threading
import random
import psutil

# ----------------------------------
# IDENTITY
# ----------------------------------

NODE_NAME = os.getenv("NODE_NAME", socket.gethostname())

# ----------------------------------
# ZMQ CONTEXT (shared)
# ----------------------------------

context = zmq.Context()

# ----------------------------------
# SUSPICIOUS PROCESS LIST
# ----------------------------------

SUSPICIOUS_PROCESSES = [
    "nmap",
    "hydra",
    "nc",
    "netcat",
    "stress",
    "stress-ng",
    "hashcat",
    "john",
    "sqlmap",
    "metasploit",
]

# ----------------------------------
# SIMULATED USERS
# ----------------------------------

FAILED_LOGIN_USERS = [
    "student1",
    "student2",
    "researcher",
    "guest",
]

PRIV_ESC_USERS = [
    "student1",
    "researcher",
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
# THREAD 1: JOB WORKER
# ==================================


def job_worker():
    """
    Receives jobs from scheduler/risk-engine.
    Marks node busy/idle for context-aware scoring.
    """

    receiver = context.socket(zmq.PULL)
    receiver.bind("tcp://*:5556")

    print(f"[{NODE_NAME}] Job worker ready on :5556")

    while True:
        try:
            job = receiver.recv_json()

            job_id = job.get("job_id", "unknown")
            job_type = job.get("job_type", "unknown")
            duration = job.get("duration", 5)

            print(
                f"[{NODE_NAME}] Executing job "
                f"{job_id} (type={job_type}, duration={duration}s)"
            )

            with job_lock:
                current_job["active"] = True
                current_job["job_type"] = job_type
                current_job["job_id"] = job_id

            time.sleep(duration)

            with job_lock:
                current_job["active"] = False
                current_job["job_type"] = None
                current_job["job_id"] = None

            print(f"[{NODE_NAME}] Completed job {job_id}")

        except Exception as e:
            print(f"[{NODE_NAME}] Job worker error: {e}")


# ==================================
# THREAD 2: TELEMETRY & DETECTION
# ==================================


def telemetry_monitor():
    """
    Collect metrics every cycle.
    Simulate attacks for demo purposes.
    Detect anomalies and send events.
    """

    sender = context.socket(zmq.PUSH)
    sender.connect("tcp://controller:5555")

    print(f"[{NODE_NAME}] " f"Telemetry monitor started -> controller:5555")

    under_attack = False
    attack_stage = 0

    while True:

        # ---------------------------
        # COLLECT METRICS
        # ---------------------------

        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        process_count = len(psutil.pids())

        failed_login_count = 0
        privilege_escalation_attempts = 0

        # ---------------------------
        # THREAT SIMULATOR
        # ---------------------------

        trigger_chance = 0.08 if NODE_NAME == "node1" else 0.03

        if not under_attack:

            if random.random() < trigger_chance:
                under_attack = True
                attack_stage = 1

                print(f"[{NODE_NAME}] " f"[SIMULATOR] Threat simulation INITIATED!")

        else:

            attack_stage = min(5, attack_stage + 1)

            print(f"[{NODE_NAME}] " f"[SIMULATOR] Escalating (Stage {attack_stage})")

        # ---------------------------
        # APPLY ATTACK STAGES
        # ---------------------------

        if under_attack:

            # Stage 1
            if attack_stage >= 1:
                cpu = 92.5

            # Stage 2
            if attack_stage >= 2:
                memory = 88.0

            # Stage 3
            if attack_stage >= 3:
                process_count = 310
                failed_login_count = random.randint(8, 20)

            # Stage 5
            if attack_stage >= 5:
                privilege_escalation_attempts = random.randint(1, 5)

        # ---------------------------
        # DEFAULT EVENT STATE
        # ---------------------------

        event_type = "NORMAL"
        reasons = []

        # ---------------------------
        # JOB CONTEXT
        # ---------------------------

        with job_lock:
            is_busy = current_job["active"]
            active_job_type = current_job["job_type"]

        # ---------------------------
        # RULE 1: HIGH CPU
        # ---------------------------

        if cpu > 80:

            if is_busy and active_job_type == "cpu":
                pass
            else:
                event_type = "SUSPICIOUS_ACTIVITY"

                reasons.append(f"High CPU usage detected: {cpu}%")

        # ---------------------------
        # RULE 2: HIGH MEMORY
        # ---------------------------

        if memory > 85:

            if is_busy and active_job_type == "memory_access":
                pass
            else:
                event_type = "SUSPICIOUS_ACTIVITY"

                reasons.append(f"High memory usage detected: {memory}%")

        # ---------------------------
        # RULE 3: PROCESS EXPLOSION
        # ---------------------------

        if process_count > 300:

            event_type = "SUSPICIOUS_ACTIVITY"

            reasons.append(f"Too many running processes: " f"{process_count}")

        # ---------------------------
        # RULE 4: SUSPICIOUS PROCESS
        # ---------------------------

        detected_suspicious = []

        for proc in psutil.process_iter(["name"]):

            try:
                pname = proc.info["name"]

                if pname and pname.lower() in SUSPICIOUS_PROCESSES:
                    detected_suspicious.append(pname)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):
                pass

        # Stage 4
        if under_attack and attack_stage >= 4:
            detected_suspicious.append("hydra")

        for pname in detected_suspicious:

            event_type = "SUSPICIOUS_ACTIVITY"

            reasons.append(f"Suspicious process detected: {pname}")

        # ---------------------------
        # RULE 5: FAILED LOGIN BURST
        # ---------------------------

        if failed_login_count > 5:

            event_type = "SUSPICIOUS_ACTIVITY"

            reasons.append(f"Excessive failed login attempts: " f"{failed_login_count}")

        # ---------------------------
        # RULE 6: PRIV ESC
        # ---------------------------

        if privilege_escalation_attempts > 0:

            event_type = "SUSPICIOUS_ACTIVITY"

            reasons.append(
                f"Privilege escalation attempts detected: "
                f"{privilege_escalation_attempts}"
            )

        # ---------------------------
        # BUILD EVENT
        # ---------------------------

        event = {
            "node": NODE_NAME,
            "cpu_usage": cpu,
            "memory_usage": memory,
            "process_count": process_count,
            "failed_login_count": failed_login_count,
            "privilege_escalation_attempts": privilege_escalation_attempts,
            "event_type": event_type,
            "reasons": reasons,
            "is_busy": is_busy,
            "active_job_type": active_job_type,
        }

        # ---------------------------
        # SEND TO CONTROLLER
        # ---------------------------

        sender.send_json(event)

        if event_type != "NORMAL":

            print(f"[{NODE_NAME}] ALERT: {reasons}")

        time.sleep(5)


# ==================================
# MAIN
# ==================================

print(f"[{NODE_NAME}] Starting agent...")

t1 = threading.Thread(
    target=job_worker,
    daemon=True,
)

t2 = threading.Thread(
    target=telemetry_monitor,
    daemon=True,
)

t1.start()
t2.start()

print(f"[{NODE_NAME}] " f"Agent running (job worker + telemetry)")

while True:
    time.sleep(1)
