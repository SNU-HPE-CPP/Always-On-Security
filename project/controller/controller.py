"""
Always-On Security — Controller
Layers 2+3+4: ZMQ Transport + Risk Engine + Auto Remediation

Five threads:
  1. receive_jobs       — pulls jobs from job_provider (:5555)
  2. scheduler          — dispatches queued jobs to idle nodes (:5556)
  3. receive_completions— tracks job completions from nodes (:5557)
  4. security_monitor   — receives telemetry from nodes (:5558), runs risk engine, remediates
  5. heartbeat_checker  — detects silent/unresponsive nodes
"""

import zmq
import docker
import json
import sqlite3
import threading
import time
from queue import Queue
from datetime import datetime

# ==================================
# DATABASE SETUP
# ==================================

DB_PATH = "/data/events.db"

db_lock = threading.Lock()


def get_db():
    """Create a new DB connection (each thread needs its own)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        node TEXT,
        cpu_usage REAL,
        memory_usage REAL,
        process_count INTEGER,
        event_type TEXT,
        reasons TEXT,
        risk_score INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT UNIQUE,
        job_type TEXT,
        duration INTEGER,
        assigned_node TEXT,
        status TEXT,
        dispatched_at TEXT,
        completed_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS node_status (
        node TEXT PRIMARY KEY,
        status TEXT,
        last_heartbeat TEXT,
        cumulative_risk INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()
    print("[DB] Tables initialized.")


init_db()

# ==================================
# ZMQ SETUP
# ==================================

context = zmq.Context()

# Port 5555: Jobs arrive from job_provider
job_receiver = context.socket(zmq.PULL)
job_receiver.bind("tcp://*:5555")

# Port 5557: Completions arrive from nodes
completion_receiver = context.socket(zmq.PULL)
completion_receiver.bind("tcp://*:5557")

# Port 5558: Security telemetry from nodes
security_receiver = context.socket(zmq.PULL)
security_receiver.bind("tcp://*:5558")

# Outbound to nodes on port 5556
node_senders = {}
NODE_LIST = ["node1", "node2", "node3", "node4"]

for node in NODE_LIST:
    sender = context.socket(zmq.PUSH)
    sender.connect(f"tcp://{node}:5556")
    node_senders[node] = sender

# ==================================
# STATE
# ==================================

job_queue = Queue()

# Node states: "idle", "busy", "quarantined"
node_state = {}
node_current_job = {}  # node -> job_type (for job-aware risk scoring)
node_last_seen = {}    # node -> timestamp (for heartbeat detection)
node_risk_scores = {}  # node -> cumulative risk

state_lock = threading.Lock()

for node in NODE_LIST:
    node_state[node] = "idle"
    node_current_job[node] = None
    node_last_seen[node] = datetime.now()
    node_risk_scores[node] = 0

# Docker client for remediation
try:
    docker_client = docker.from_env()
    print("[DOCKER] Connected to Docker daemon.")
except Exception as e:
    docker_client = None
    print(f"[DOCKER] WARNING: Cannot connect to Docker: {e}")

# ==================================
# THREAD 1: RECEIVE JOBS
# ==================================

def receive_jobs():
    """Pull jobs from job_provider on :5555 and enqueue them."""
    print("[JOBS] Listening for jobs on :5555")

    while True:
        job = job_receiver.recv_json()
        job_queue.put(job)
        print(f"[QUEUE] Job {job['job_id'][:8]}... queued (size={job_queue.qsize()})")

# ==================================
# THREAD 2: SCHEDULER
# ==================================

def scheduler():
    """Dispatch queued jobs to idle nodes."""
    print("[SCHEDULER] Running")

    while True:
        if not job_queue.empty():
            with state_lock:
                idle_node = None
                for node, status in node_state.items():
                    if status == "idle":
                        idle_node = node
                        break

            if idle_node:
                job = job_queue.get()
                job_id = job["job_id"]
                job_type = job.get("job_type", "unknown")

                node_senders[idle_node].send_json(job)

                with state_lock:
                    node_state[idle_node] = "busy"
                    node_current_job[idle_node] = job_type

                # Store job in DB
                try:
                    conn = get_db()
                    with db_lock:
                        conn.execute("""
                        INSERT OR IGNORE INTO jobs
                            (job_id, job_type, duration, assigned_node, status, dispatched_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            job_id,
                            job_type,
                            job.get("duration", 0),
                            idle_node,
                            "running",
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        ))
                        conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"[DB] Error storing job: {e}")

                print(f"[SCHEDULER] {job_id[:8]}... -> {idle_node} (type={job_type})")

        time.sleep(1)

# ==================================
# THREAD 3: RECEIVE COMPLETIONS
# ==================================

def receive_completions():
    """Track job completions from nodes on :5557."""
    print("[COMPLETIONS] Listening on :5557")

    while True:
        msg = completion_receiver.recv_json()
        node = msg["node"]
        job_id = msg["job_id"]

        with state_lock:
            node_state[node] = "idle"
            node_current_job[node] = None

        # Update job status in DB
        try:
            conn = get_db()
            with db_lock:
                conn.execute("""
                UPDATE jobs SET status = ?, completed_at = ?
                WHERE job_id = ?
                """, (
                    "completed",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    job_id,
                ))
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] Error updating job: {e}")

        print(f"[COMPLETE] {job_id[:8]}... finished on {node}")

# ==================================
# THREAD 4: SECURITY MONITOR
# ==================================

def security_monitor():
    """
    Receive telemetry events from nodes on :5558.
    Run risk engine, store events, and auto-remediate.
    """
    print("[SECURITY] Monitoring on :5558")

    while True:
        message = security_receiver.recv_json()

        node = message["node"]
        reasons = message.get("reasons", [])
        event_type = message.get("event_type", "NORMAL")

        # Update heartbeat
        with state_lock:
            node_last_seen[node] = datetime.now()

        # ------- RISK CALCULATION -------
        risk_increment = 0

        for reason in reasons:
            if "CPU" in reason:
                risk_increment += 20
            if "memory" in reason:
                risk_increment += 20
            if "Suspicious process" in reason:
                risk_increment += 40
            if "Too many" in reason:
                risk_increment += 25

        with state_lock:
            node_risk_scores[node] = node_risk_scores.get(node, 0) + risk_increment
            current_risk = node_risk_scores[node]

            # Decay risk slowly for normal events (self-healing)
            if event_type == "NORMAL" and node_risk_scores[node] > 0:
                node_risk_scores[node] = max(0, node_risk_scores[node] - 5)
                current_risk = node_risk_scores[node]

        # ------- SEVERITY & REMEDIATION -------
        severity = "LOW"

        if current_risk >= 100:
            severity = "CRITICAL"
            print(f"[SECURITY] CRITICAL: {node} risk={current_risk}")

            # Auto-quarantine
            with state_lock:
                if node_state[node] != "quarantined":
                    node_state[node] = "quarantined"
                    node_current_job[node] = None
                    print(f"[REMEDIATION] Quarantining {node}")

                    if docker_client:
                        try:
                            container = docker_client.containers.get(node)
                            container.stop()
                            print(f"[REMEDIATION] {node} stopped successfully.")
                        except Exception as e:
                            print(f"[REMEDIATION] Failed to stop {node}: {e}")

        elif current_risk >= 50:
            severity = "MEDIUM"
            print(f"[SECURITY] MEDIUM risk on {node}: {current_risk}")

        # ------- STORE EVENT IN DB -------
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            conn = get_db()
            with db_lock:
                conn.execute("""
                INSERT INTO events
                    (timestamp, node, cpu_usage, memory_usage,
                     process_count, event_type, reasons, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp,
                    node,
                    message.get("cpu_usage", 0),
                    message.get("memory_usage", 0),
                    message.get("process_count", 0),
                    event_type,
                    json.dumps(reasons),
                    current_risk,
                ))

                # Update node_status table
                conn.execute("""
                INSERT INTO node_status (node, status, last_heartbeat, cumulative_risk)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(node) DO UPDATE SET
                    status = excluded.status,
                    last_heartbeat = excluded.last_heartbeat,
                    cumulative_risk = excluded.cumulative_risk
                """, (
                    node,
                    node_state.get(node, "unknown"),
                    timestamp,
                    current_risk,
                ))

                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] Error storing event: {e}")

# ==================================
# THREAD 5: HEARTBEAT CHECKER
# ==================================

HEARTBEAT_TIMEOUT = 30  # seconds

def heartbeat_checker():
    """Detect nodes that have stopped sending telemetry."""
    print(f"[HEARTBEAT] Checker running (timeout={HEARTBEAT_TIMEOUT}s)")

    # Give nodes time to start up
    time.sleep(15)

    while True:
        now = datetime.now()

        with state_lock:
            for node in NODE_LIST:
                if node_state[node] == "quarantined":
                    continue

                last = node_last_seen.get(node)
                if last is None:
                    continue

                delta = (now - last).total_seconds()

                if delta > HEARTBEAT_TIMEOUT:
                    print(f"[HEARTBEAT] WARNING: {node} unresponsive ({delta:.0f}s since last telemetry)")

                    # Store unresponsive event
                    try:
                        conn = get_db()
                        with db_lock:
                            conn.execute("""
                            INSERT INTO events
                                (timestamp, node, cpu_usage, memory_usage,
                                 process_count, event_type, reasons, risk_score)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                now.strftime("%Y-%m-%d %H:%M:%S"),
                                node, 0, 0, 0,
                                "NODE_UNRESPONSIVE",
                                json.dumps([f"No telemetry for {delta:.0f}s"]),
                                node_risk_scores.get(node, 0),
                            ))

                            conn.execute("""
                            INSERT INTO node_status (node, status, last_heartbeat, cumulative_risk)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(node) DO UPDATE SET
                                status = excluded.status,
                                last_heartbeat = excluded.last_heartbeat
                            """, (
                                node, "unresponsive",
                                now.strftime("%Y-%m-%d %H:%M:%S"),
                                node_risk_scores.get(node, 0),
                            ))

                            conn.commit()
                        conn.close()
                    except Exception as e:
                        print(f"[DB] Error storing heartbeat event: {e}")

        time.sleep(10)

# ==================================
# MAIN
# ==================================

print("=" * 50)
print("  ALWAYS-ON SECURITY CONTROLLER")
print("=" * 50)

threads = [
    ("JobReceiver", receive_jobs),
    ("Scheduler", scheduler),
    ("Completions", receive_completions),
    ("SecurityMonitor", security_monitor),
    ("HeartbeatChecker", heartbeat_checker),
]

for name, target in threads:
    t = threading.Thread(target=target, name=name, daemon=True)
    t.start()
    print(f"[MAIN] Started thread: {name}")

print("[CONTROLLER] All systems online.\n")

while True:
    time.sleep(1)