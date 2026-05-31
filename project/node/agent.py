"""
Always-On Security — Node Agent
Layer 1: Telemetry collection + Job execution

Two threads run concurrently:
  1. Job Worker   — receives HPC jobs from controller, executes them, reports completion
  2. Telemetry    — collects system metrics, detects anomalies, sends security events
"""

import zmq
import time
import os
import socket
import threading
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
# CURRENT JOB TRACKING
# (shared between threads for
#  job-aware risk scoring context)
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
    Receives jobs from the controller on port 5556,
    executes them (simulated), and sends completion
    messages back on port 5557.
    """

    # Receive jobs from controller
    receiver = context.socket(zmq.PULL)
    receiver.bind("tcp://*:5556")

    # Send completions back
    completion_sender = context.socket(zmq.PUSH)
    completion_sender.connect("tcp://controller:5557")

    print(f"[{NODE_NAME}] Job worker ready on :5556")

    while True:

        job = receiver.recv_json()

        job_id = job["job_id"]
        job_type = job.get("job_type", "unknown")
        duration = job.get("duration", 5)

        print(f"[{NODE_NAME}] Executing job {job_id} (type={job_type}, duration={duration}s)")

        # Mark job as active (for telemetry thread)
        with job_lock:
            current_job["active"] = True
            current_job["job_type"] = job_type
            current_job["job_id"] = job_id

        # Simulate execution
        time.sleep(duration)

        # Mark job complete
        with job_lock:
            current_job["active"] = False
            current_job["job_type"] = None
            current_job["job_id"] = None

        print(f"[{NODE_NAME}] Completed job {job_id}")

        completion_sender.send_json({
            "job_id": job_id,
            "node": NODE_NAME,
            "job_type": job_type,
            "duration": duration,
        })

# ==================================
# THREAD 2: TELEMETRY & ANOMALY
# ==================================

def telemetry_monitor():
    """
    Collects system metrics via psutil every 5 seconds,
    runs rule-based anomaly detection, and sends
    security events to the controller on port 5558.
    """

    # Send security events to controller
    sender = context.socket(zmq.PUSH)
    sender.connect("tcp://controller:5558")

    print(f"[{NODE_NAME}] Telemetry monitor started -> :5558")

    while True:

        # ---- Collect telemetry ----
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        process_count = len(psutil.pids())

        # ---- Default state ----
        event_type = "NORMAL"
        reasons = []

        # ---- Get current job context ----
        with job_lock:
            is_busy = current_job["active"]
            active_job_type = current_job["job_type"]

        # ---- RULE 1: High CPU ----
        if cpu > 80:
            # Job-aware: if running a CPU job, high CPU is expected
            if is_busy and active_job_type == "cpu":
                pass  # Expected behavior, don't flag
            else:
                event_type = "SUSPICIOUS_ACTIVITY"
                reasons.append(f"High CPU usage detected: {cpu}%")

        # ---- RULE 2: High Memory ----
        if memory > 85:
            if is_busy and active_job_type == "memory_access":
                pass  # Expected for memory-intensive jobs
            else:
                event_type = "SUSPICIOUS_ACTIVITY"
                reasons.append(f"High memory usage detected: {memory}%")

        # ---- RULE 3: Too many processes ----
        if process_count > 300:
            event_type = "SUSPICIOUS_ACTIVITY"
            reasons.append(f"Too many running processes: {process_count}")

        # ---- RULE 4: Suspicious process names ----
        for proc in psutil.process_iter(['name']):
            try:
                pname = proc.info['name']
                if pname and pname.lower() in SUSPICIOUS_PROCESSES:
                    event_type = "SUSPICIOUS_ACTIVITY"
                    reasons.append(f"Suspicious process detected: {pname}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # ---- Build event ----
        event = {
            "node": NODE_NAME,
            "cpu_usage": cpu,
            "memory_usage": memory,
            "process_count": process_count,
            "event_type": event_type,
            "reasons": reasons,
            "is_busy": is_busy,
            "active_job_type": active_job_type,
        }

        # Send to controller
        sender.send_json(event)

        if event_type != "NORMAL":
            print(f"[{NODE_NAME}] ALERT: {reasons}")

        # Wait before next cycle
        time.sleep(5)

# ==================================
# MAIN
# ==================================

print(f"[{NODE_NAME}] Starting agent...")

t1 = threading.Thread(target=job_worker, daemon=True)
t2 = threading.Thread(target=telemetry_monitor, daemon=True)

t1.start()
t2.start()

print(f"[{NODE_NAME}] Agent running (job worker + telemetry)")

while True:
    time.sleep(1)
