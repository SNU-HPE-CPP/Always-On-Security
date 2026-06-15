"""
Always-On Security — Host Observer (cluster_observer.py)

Monitors tenant containers externally via the Docker Daemon API.
Gathers CPU/Memory, checks processes against policy, and verifies
config file integrity (FIM) using Docker's get_archive (cp) API —
no commands are executed inside tenant containers.
"""

import hashlib
import io
import os
import sys
import tarfile
import time
import logging
import zmq
import yaml
import docker

from secure_messenger import SecureMessenger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cluster_observer")

CONFIG_DIR = "/opt/security/config"
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "tcp://controller:5555")

# Files to monitor for configuration tampering
MONITORED_FILES = ["/etc/hosts", "/etc/passwd", "/etc/ssh/sshd_config"]


def load_allowlist() -> list:
    path = os.path.join(CONFIG_DIR, "allowlist.yaml")
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                return data.get("allowed_nodes", ["node1", "node2", "node3", "node4"])
        except Exception as e:
            log.error(f"Error loading allowlist: {e}")
    return ["node1", "node2", "node3", "node4"]


def load_process_policy() -> tuple[str, set[str], set[str]]:
    path = os.path.join(CONFIG_DIR, "process_policy.yaml")
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                mode = data.get("mode", "denylist")
                denylist = set(data.get("denylist", []) or [])
                allowlist = set(data.get("allowlist", []) or [])
                return mode, denylist, allowlist
        except Exception as e:
            log.error(f"Error loading process policy: {e}")
    return "denylist", set(), set()


def load_config_hashes() -> dict[str, str]:
    path = os.path.join(CONFIG_DIR, "config_hashes.yaml")
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                return {k: v for k, v in data.items() if isinstance(v, str)}
        except Exception as e:
            log.error(f"Error loading config hashes: {e}")
    return {}


def get_container_stats(container) -> tuple[float, float]:
    """Calculate CPU and Memory usage percentages from container stats."""
    try:
        stats = container.stats(stream=False)
        
        # CPU calculation
        cpu_stats = stats.get("cpu_stats", {})
        precpu_stats = stats.get("precpu_stats", {})
        
        cpu_usage_pct = 0.0
        cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)
        
        if system_delta > 0 and cpu_delta > 0:
            online_cpus = cpu_stats.get("online_cpus", len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", []))) or 1
            cpu_usage_pct = (cpu_delta / system_delta) * online_cpus * 100.0
            
        # Memory calculation
        mem_stats = stats.get("memory_stats", {})
        mem_usage = mem_stats.get("usage", 0)
        # Deduct inactive file cache to get active memory usage
        cache = mem_stats.get("stats", {}).get("inactive_file", 0)
        active_mem = max(0, mem_usage - cache)
        mem_limit = mem_stats.get("limit", 1)
        mem_usage_pct = (active_mem / mem_limit) * 100.0
        
        return min(100.0, cpu_usage_pct), min(100.0, mem_usage_pct)
    except Exception as e:
        log.debug(f"Failed to fetch stats for {container.name}: {e}")
        return 0.0, 0.0


def get_container_processes(container) -> tuple[int, list[str]]:
    """Retrieve process count and process CMD/names from container top."""
    try:
        top = container.top()
        titles = [t.upper() for t in top.get("Titles", [])]
        processes = top.get("Processes", [])
        
        cmd_idx = -1
        for i, title in enumerate(titles):
            if "CMD" in title or "COMMAND" in title:
                cmd_idx = i
                break
                
        proc_names = []
        if cmd_idx != -1:
            for proc in processes:
                cmd_line = proc[cmd_idx]
                if cmd_line:
                    # Parse command name
                    exe = cmd_line.split()[0]
                    proc_name = os.path.basename(exe).strip("[]:")
                    proc_names.append(proc_name)
                    
        return len(processes), proc_names
    except Exception as e:
        log.debug(f"Failed to fetch processes for {container.name}: {e}")
        return 0, []


def check_container_file_hash(container, file_path: str) -> str | None:
    """Compute sha256 of a file inside the container using Docker's copy API.

    Uses container.get_archive() (Docker cp) to stream the file content out of
    the container's overlay filesystem without executing any process inside the
    tenant container. This satisfies the HPC trust-boundary requirement that the
    Host_Observer must NOT run arbitrary commands inside Workload_Zone containers.
    """
    try:
        # get_archive returns a raw tar stream of the file at file_path
        stream, _stat = container.get_archive(file_path)
        raw = b"".join(stream)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            # The archive contains exactly one member (the file itself)
            member = tar.getmembers()[0]
            f = tar.extractfile(member)
            if f is None:
                return None
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
            return h.hexdigest()
    except Exception as e:
        log.debug(f"Failed to hash {file_path} inside {container.name} via archive API: {e}")
    return None


def main():
    log.info("Host/Cluster Observer starting up...")
    
    # Wait for Controller
    ctx = zmq.Context()
    sender = ctx.socket(zmq.PUSH)
    sender.connect(CONTROLLER_URL)
    log.info(f"Connected to Controller at {CONTROLLER_URL}")
    
    # Initialize Docker client
    try:
        client = docker.from_env()
        log.info("Connected to Docker daemon successfully.")
    except Exception as e:
        log.critical(f"Cannot connect to Docker daemon: {e}")
        sys.exit(1)
        
    # Keep track of Node Messengers (for sequences & machine IDs)
    messengers: dict[str, SecureMessenger] = {}
    
    # Keep track of baseline file hashes per node container
    # node -> file_path -> sha256
    fim_baselines: dict[str, dict[str, str]] = {}
    
    # Load config hashes from file as first reference
    global_baselines = load_config_hashes()
    log.info(f"Loaded config baselines: {global_baselines}")
    
    while True:
        try:
            nodes = load_allowlist()
            mode, denylist, allowlist = load_process_policy()
            
            for node in nodes:
                try:
                    container = client.containers.get(node)
                    container.reload()
                    
                    if container.status != "running":
                        log.debug(f"Node container {node} is not running (status={container.status})")
                        continue
                        
                    # Retrieve stable container ID to use as machine_id
                    cid = container.id
                    
                    if node not in messengers:
                        # Instantiate a messenger with the actual container ID
                        messengers[node] = SecureMessenger(node_name=node, machine_id=cid)
                        
                    messenger = messengers[node]
                    
                    # 1. Resource Metrics
                    cpu, mem = get_container_stats(container)
                    proc_count, proc_names = get_container_processes(container)
                    
                    # 2. Process Policy Verification
                    unauthorized_procs = []
                    reasons = []
                    event_type = "NORMAL"
                    
                    if mode == "denylist":
                        for name in proc_names:
                            if name in denylist:
                                unauthorized_procs.append({"name": name, "pid": 0})
                                reasons.append(f"Unauthorized process '{name}' detected (denylist)")
                                event_type = "SUSPICIOUS_ACTIVITY"
                    elif mode == "allowlist" and allowlist:
                        for name in proc_names:
                            # Skip basic system and agent process names
                            if name in ["python", "bash", "sh", "agent.py"]:
                                continue
                            if name not in allowlist:
                                unauthorized_procs.append({"name": name, "pid": 0})
                                reasons.append(f"Unauthorized process '{name}' detected (not in allowlist)")
                                event_type = "SUSPICIOUS_ACTIVITY"
                                
                    # 3. FIM File Tamper Verification
                    config_tamper = False
                    tampered_files = []
                    
                    if node not in fim_baselines:
                        fim_baselines[node] = {}
                        
                    for fpath in MONITORED_FILES:
                        current_hash = check_container_file_hash(container, fpath)
                        if not current_hash:
                            continue
                            
                        # Resolve baseline
                        expected_hash = global_baselines.get(fpath)
                        if not expected_hash:
                            # Cache the first seen hash as the baseline for this node if not predefined
                            if fpath not in fim_baselines[node]:
                                fim_baselines[node][fpath] = current_hash
                            expected_hash = fim_baselines[node][fpath]
                            
                        if current_hash != expected_hash:
                            config_tamper = True
                            tampered_files.append({
                                "file": fpath,
                                "expected": expected_hash,
                                "actual": current_hash
                            })
                            reasons.append(f"Config tamper on {fpath}")
                            event_type = "SUSPICIOUS_ACTIVITY"
                            
                            # Update baseline in memory to avoid repeating alert indefinitely
                            fim_baselines[node][fpath] = current_hash
                            global_baselines[fpath] = current_hash
                            
                            # Construct and send a FIM Event payload
                            fim_payload = {
                                "node": node,
                                "event_type": "FIM_EVENT",
                                "reasons": [f"Config file integrity check failed for {fpath}"],
                                "cpu_usage": cpu,
                                "memory_usage": mem,
                                "process_count": proc_count,
                                "is_busy": False,
                                "active_job_type": None,
                                "fim_details": {
                                    "fim_event_type": "FIM_FILE_MODIFIED",
                                    "file_path": fpath,
                                    "current_state": {
                                        "sha256": current_hash,
                                        "file_size": 0,
                                        "permissions": ""
                                    }
                                }
                            }
                            signed_fim = messenger.sign(fim_payload)
                            sender.send_json(signed_fim)
                            log.warning(f"Sent FIM_EVENT for {node}: tamper on {fpath}")
                            
                    # 4. Standard Telemetry Payload
                    telemetry_payload = {
                        "node": node,
                        "cpu_usage": round(cpu, 2),
                        "memory_usage": round(mem, 2),
                        "process_count": proc_count,
                        "failed_login_count": 0,
                        "privilege_escalation_attempts": 0,
                        "event_type": event_type,
                        "reasons": reasons,
                        "is_busy": False,
                        "active_job_type": None,
                        "config_tamper": config_tamper,
                        "tampered_files": tampered_files,
                        "unauthorized_procs": unauthorized_procs,
                    }
                    
                    signed_telemetry = messenger.sign(telemetry_payload)
                    sender.send_json(signed_telemetry)
                    log.debug(f"Dispatched telemetry for {node} (cpu={cpu:.1f}%, mem={mem:.1f}%, procs={proc_count})")
                    
                except docker.errors.NotFound:
                    log.debug(f"Container {node} not found.")
                except Exception as e:
                    log.error(f"Error checking node {node}: {e}", exc_info=True)
                    
        except Exception as e:
            log.error(f"Loop error in Host Observer: {e}")
            
        time.sleep(5)


if __name__ == "__main__":
    main()
