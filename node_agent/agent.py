"""
Always-On Security — Node Agent
Dual-threaded agent + FIM watcher thread:
  1. Telemetry Monitor — collects system metrics, detects anomalies, sends security events
  2. Job Worker — receives job assignments, marks node as busy/idle for context-aware detection
  3. FIM Monitor — watches configured files/directories using Linux inotify and hashes changes

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
import hashlib
import yaml
from inotify_simple import INotify, flags

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
# SECURE MESSENGER (shared, thread-safe seq counter)
# ----------------------------------

messenger = SecureMessenger(NODE_NAME)

# ----------------------------------
# SECURITY COLLECTOR (shared)
# ----------------------------------

security_collector = SecurityCollector()

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

# ----------------------------------
# FIM CONFIGURATION & BASELINES
# ----------------------------------

baseline = {}
fim_config = {}

# Paths to watch
critical_files = []
watched_directories = []

def load_fim_config():
    global critical_files, watched_directories, fim_config
    config_path = os.path.join(os.path.dirname(__file__), "fim_config.yaml")
    try:
        with open(config_path) as f:
            fim_config = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[{NODE_NAME}] Failed to load FIM config: {e}")
        fim_config = {}

    critical_files = fim_config.get("critical_files", [])
    watched_directories = fim_config.get("watched_directories", [])

    # Ensure critical directories exist
    for d in watched_directories:
        os.makedirs(d, exist_ok=True)

    # Ensure critical files exist so inotify can watch them
    for path in critical_files:
        parent = os.path.dirname(path)
        os.makedirs(parent, exist_ok=True)
        if not os.path.exists(path):
            try:
                with open(path, "w") as f:
                    f.write("# Always-On Security Monitored File\n")
                print(f"[{NODE_NAME}] Created missing critical file: {path}")
            except Exception as e:
                print(f"[{NODE_NAME}] Failed to pre-create {path}: {e}")

def get_file_metadata(path):
    try:
        stat = os.stat(path)
        size = stat.st_size
        perms = oct(stat.st_mode & 0o777)  # e.g., '0o644'
        owner = f"{stat.st_uid}:{stat.st_gid}"

        # Check if we should hash the file
        should_hash = False
        if path in critical_files:
            should_hash = True
        else:
            for d in watched_directories:
                if path.startswith(d):
                    # We compute hash for normal files inside watched directories unless too big
                    should_hash = True
                    break

        sha256 = ""
        if should_hash and os.path.isfile(path) and size < 50 * 1024 * 1024:
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            sha256 = hasher.hexdigest()

        return {
            "sha256": sha256,
            "size": size,
            "permissions": perms,
            "owner_group": owner,
            "exists": True
        }
    except FileNotFoundError:
        return {"exists": False}
    except Exception as e:
        print(f"[{NODE_NAME}] Error reading metadata for {path}: {e}")
        return {"exists": False}

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
                # SIMULATE FILE MODIFICATION on /etc/hosts
                try:
                    with open('/etc/hosts', 'a') as f:
                        f.write(f"\n127.0.0.1 simulated-malicious-{attack_stage}.com\n")
                    print(f"[{NODE_NAME}] [SIMULATOR] Appended host mapping to /etc/hosts")
                except Exception as e:
                    print(f"[{NODE_NAME}] [SIMULATOR] Failed to modify /etc/hosts: {e}")
            if attack_stage >= 3:
                process_count = 310  # Triggers PROCESS_COUNT rule
                failed_login_count = random.randint(8, 20)

                # SIMULATE PERMISSION CHANGE on /etc/passwd
                try:
                    os.chmod('/etc/passwd', 0o777)  # nosec B103 # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions — intentional attack simulator: triggers permission-change detection rules
                    print(f"[{NODE_NAME}] [SIMULATOR] Changed /etc/passwd permissions to 0777")
                except Exception as e:
                    print(f"[{NODE_NAME}] [SIMULATOR] Failed to chmod /etc/passwd: {e}")
            if attack_stage >= 4:
                # SIMULATE FILE DELETION on /etc/ssh/sshd_config
                try:
                    if os.path.exists('/etc/ssh/sshd_config'):
                        os.remove('/etc/ssh/sshd_config')
                        print(f"[{NODE_NAME}] [SIMULATOR] Deleted /etc/ssh/sshd_config")
                except Exception as e:
                    print(f"[{NODE_NAME}] [SIMULATOR] Failed to delete /etc/ssh/sshd_config: {e}")

        
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
        # SECURITY COLLECTOR SNAPSHOT
        # ---------------------------

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

        if sec.get("network_threat"):
            event_type = "SUSPICIOUS_ACTIVITY"
            for anomaly in sec.get("network_anomalies", []):
                reasons.append(f"Network threat: {anomaly}")

        # ---------------------------
        # BUILD EVENT
        # ---------------------------

        raw_payload = {
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
            "config_tamper":      sec.get("config_tamper", False),
            "tampered_files":     sec.get("tampered_files", []),
            "ssh_connections":    sec.get("ssh_connections", 0),
            "lateral_peers":      sec.get("lateral_peers", []),
            "peer_contact_count": sec.get("peer_contact_count", 0),
            "unauthorized_procs": sec.get("unauthorized_procs", []),
            "network_threat": sec.get("network_threat", False),
            "network_anomalies": sec.get("network_anomalies", []),
            "unexpected_listeners": sec.get("unexpected_listeners", []),
            "unexpected_egress": sec.get("unexpected_egress", []),
            "remote_connection_count": sec.get("remote_connection_count", 0),
            "remote_target_count": sec.get("remote_target_count", 0),
        }

        # ---------------------------
        # SIGN AND SEND
        # ---------------------------

        signed_msg = messenger.sign(raw_payload)
        sender.send_json(signed_msg)

        if event_type != "NORMAL":

            print(f"[{NODE_NAME}] ALERT: {reasons}")

        time.sleep(5)

# ==================================
# THREAD 3: FILE INTEGRITY MONITOR (FIM)
# ==================================

def fim_monitor():
    """
    Watches files and directories using Linux inotify (inotify-simple)
    for creations, modifications, deletions, and permission changes.
    Generates and transmits real-time FIM events to the controller.
    """
    global baseline

    # Establish connection to controller
    sender = context.socket(zmq.PUSH)
    sender.connect("tcp://controller:5555")

    # Initialize baselines for critical files
    for path in critical_files:
        meta = get_file_metadata(path)
        if meta["exists"]:
            baseline[path] = meta
            print(f"[{NODE_NAME}] FIM baseline initialized: {path} -> {meta['sha256'][:8] or 'meta-only'}")

    # Initialize baselines for watched directories recursively
    for d in watched_directories:
        for root, _, files in os.walk(d):
            for file in files:
                full_path = os.path.join(root, file)
                meta = get_file_metadata(full_path)
                if meta["exists"]:
                    baseline[full_path] = meta
                    print(f"[{NODE_NAME}] FIM baseline initialized: {full_path} -> {meta['sha256'][:8] or 'meta-only'}")

    # Set up inotify watches
    inotify = INotify()
    watch_descriptors = {}

    # Gather distinct directories to watch
    dirs_to_watch = set(watched_directories)
    for path in critical_files:
        parent = os.path.dirname(path)
        if os.path.exists(parent):
            dirs_to_watch.add(parent)

    mask = (flags.MODIFY | flags.CREATE | flags.DELETE | 
            flags.ATTRIB | flags.MOVED_TO | flags.MOVED_FROM)

    for d in dirs_to_watch:
        try:
            wd = inotify.add_watch(d, mask)
            watch_descriptors[wd] = d
            print(f"[{NODE_NAME}] FIM registering watch on: {d}")
        except Exception as e:
            print(f"[{NODE_NAME}] FIM watch failed for {d}: {e}")

    print(f"[{NODE_NAME}] FIM monitor started.")

    while True:
        try:
            # Block until event occurs
            events = inotify.read()
            for event in events:
                parent_dir = watch_descriptors.get(event.wd)
                if not parent_dir or not event.name:
                    continue

                full_path = os.path.join(parent_dir, event.name)

                # Check if file path is monitored
                is_monitored = False
                if full_path in critical_files:
                    is_monitored = True
                else:
                    for d in watched_directories:
                        if full_path.startswith(d):
                            is_monitored = True
                            break

                if not is_monitored:
                    continue

                # Short delay to allow write completion (debouncing)
                time.sleep(0.2)

                curr = get_file_metadata(full_path)
                prev = baseline.get(full_path)

                fim_event_type = None
                reasons = []

                # Evaluate flags
                is_delete = event.mask & (flags.DELETE | flags.MOVED_FROM)
                is_create = event.mask & (flags.CREATE | flags.MOVED_TO)

                # Deletion case
                if is_delete or (prev and not curr["exists"]):
                    fim_event_type = "FIM_FILE_DELETED"
                    reasons.append(f"deleted")
                    baseline.pop(full_path, None)

                # Creation case
                elif not prev and curr["exists"]:
                    fim_event_type = "FIM_FILE_CREATED"
                    reasons.append(f"created")
                    baseline[full_path] = curr

                # Modification case
                elif prev and curr["exists"]:
                    changes = []
                    # Check SHA256 (for files that are hashed)
                    if prev["sha256"] and curr["sha256"] and prev["sha256"] != curr["sha256"]:
                        fim_event_type = "FIM_FILE_MODIFIED"
                        changes.append("modified")
                    elif prev["size"] != curr["size"]:
                        fim_event_type = "FIM_FILE_MODIFIED"
                        changes.append("modified")
                    
                    # Check permissions/owner
                    if prev["permissions"] != curr["permissions"] or prev["owner_group"] != curr["owner_group"]:
                        if not fim_event_type:
                            fim_event_type = "FIM_PERMISSION_CHANGED"
                        changes.append("permission")

                    if fim_event_type:
                        reasons.append(f"{', '.join(changes)}")
                        baseline[full_path] = curr

                # Dispatch ZMQ event if violation found
                if fim_event_type:
                    # Satisfy main telemetry required fields to pass controller schemas
                    cpu = psutil.cpu_percent()
                    memory = psutil.virtual_memory().percent
                    process_count = len(psutil.pids())

                    # Format the main reason string for rule engine mapping
                    reason_msg = f"FIM {reasons[0].capitalize()}: {full_path}"

                    event_payload = {
                        "node": NODE_NAME,
                        "cpu_usage": cpu,
                        "memory_usage": memory,
                        "process_count": process_count,
                        "failed_login_count": 0,
                        "privilege_escalation_attempts": 0,
                        "event_type": "FIM_EVENT",
                        "reasons": [reason_msg],
                        "is_busy": False,
                        "active_job_type": None,
                        "fim_details": {
                            "fim_event_type": fim_event_type,
                            "file_path": full_path,
                            "previous_state": prev,
                            "current_state": curr if curr["exists"] else None
                        }
                    }
                    signed_fim = messenger.sign(event_payload)
                    sender.send_json(signed_fim)
                    print(f"[{NODE_NAME}] FIM ALERT TRANSMITTED: {reason_msg} ({fim_event_type})")

        except Exception as e:
            print(f"[{NODE_NAME}] FIM monitoring error: {e}")
            time.sleep(2)

# ==================================
# THREAD 4: SECURITY COLLECTOR
# ==================================

def security_collector_thread():
    """Runs the SecurityCollector main loop in a background thread."""
    security_collector.run()


# ==================================
# MAIN
# ==================================

print(f"[{NODE_NAME}] Starting agent (telemetry + FIM + security collector)...")

load_fim_config()

t1 = threading.Thread(target=job_worker,               daemon=True, name="JobWorker")
t2 = threading.Thread(target=telemetry_monitor,        daemon=True, name="TelemetryMonitor")
t3 = threading.Thread(target=fim_monitor,              daemon=True, name="FIMMonitor")
t4 = threading.Thread(target=security_collector_thread, daemon=True, name="SecurityCollector")

t1.start()
t2.start()
t3.start()
t4.start()

print(f"[{NODE_NAME}] Agent running (job worker + telemetry + FIM + security collector)")

while True:
    time.sleep(1)
