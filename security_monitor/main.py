import os
import sys
import time
import queue
import logging
import signal
import subprocess
import threading

from docker_collector import run_docker_collector
from network_collector import run_network_collector
from threat_correlator import ThreatCorrelator
from policy_engine import PolicyEngine
from event_forwarder import EventForwarder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("supervisor")

# Subprocess references
suricata_proc = None
zeek_proc = None

def run_subprocess(cmd: list[str], stdout_file: str, stderr_file: str) -> subprocess.Popen:
    """Launch a subprocess, redirecting stdout/stderr to log files.

    Uses an explicit list form (no shell=True) to prevent command injection.
    The file handles are intentionally kept open for the lifetime of the
    subprocess — closing them would sever the redirect.
    """
    os.makedirs(os.path.dirname(stdout_file), exist_ok=True)
    out = open(stdout_file, "w")  # noqa: WPS515 — intentional long-lived fd
    err = open(stderr_file, "w")  # noqa: WPS515 — intentional long-lived fd
    return subprocess.Popen(cmd, stdout=out, stderr=err)

def cleanup():
    global suricata_proc, zeek_proc
    log.info("Cleaning up sub-processes...")
    if suricata_proc:
        try:
            log.info("Terminating Suricata...")
            suricata_proc.terminate()
            suricata_proc.wait(timeout=5)
        except Exception:
            suricata_proc.kill()
    if zeek_proc:
        try:
            log.info("Terminating Zeek emulator...")
            zeek_proc.terminate()
            zeek_proc.wait(timeout=5)
        except Exception:
            zeek_proc.kill()

def sig_handler(signum, frame):
    log.warning(f"Received signal {signum}. Gracefully shutting down...")
    cleanup()
    sys.exit(0)

def main():
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    
    # 1. Prepare environment directories
    os.makedirs("/var/log/security", exist_ok=True)
    os.makedirs("/var/log/zeek", exist_ok=True)
    os.makedirs("/var/log/suricata", exist_ok=True)
    os.makedirs("/etc/suricata/rules", exist_ok=True)
    
    # Copy Suricata rules to target system paths
    try:
        subprocess.run(
            ["cp", "/opt/security-monitor/suricata/hpc-scan.rules", "/etc/suricata/rules/hpc-scan.rules"],
            check=True,
        )
        subprocess.run(
            ["cp", "/opt/security-monitor/suricata/threshold.conf", "/etc/suricata/threshold.conf"],
            check=True,
        )
    except Exception as e:
        log.error(f"Failed to copy Suricata rules: {e}")

    # 2. Launch background network security subprocesses
    global suricata_proc, zeek_proc
    suricata_cmd = [
        "sudo", "suricata", "-i", "eth0",
        "-c", "/opt/security-monitor/suricata/suricata.yaml",
        "-l", "/var/log/suricata",
    ]
    zeek_cmd = ["python3", "/opt/security-monitor/zeek/zeek_emulator.py"]
    
    log.info("Launching Suricata...")
    suricata_proc = run_subprocess(suricata_cmd, "/var/log/security/suricata.stdout", "/var/log/security/suricata.stderr")
    
    log.info("Launching Zeek Emulator...")
    zeek_proc = run_subprocess(zeek_cmd, "/var/log/security/zeek.stdout", "/var/log/security/zeek.stderr")
    
    # 3. Create pipeline queues
    raw_queue = queue.Queue()
    correlator_queue = queue.Queue()
    forward_queue = queue.Queue()
    
    # 4. Start pipeline threads
    t_docker = threading.Thread(target=run_docker_collector, args=(raw_queue,), name="DockerCollector", daemon=True)
    t_network = threading.Thread(target=run_network_collector, args=(raw_queue,), name="NetworkCollector", daemon=True)
    
    correlator = ThreatCorrelator(raw_queue, correlator_queue)
    t_correlator = threading.Thread(target=correlator.run, name="ThreatCorrelator", daemon=True)
    
    policy_engine = PolicyEngine(correlator_queue, forward_queue)
    t_policy = threading.Thread(target=policy_engine.run, name="PolicyEngine", daemon=True)
    
    forwarder = EventForwarder(forward_queue)
    t_forward = threading.Thread(target=forwarder.run, name="EventForwarder", daemon=True)
    
    t_docker.start()
    t_network.start()
    t_correlator.start()
    t_policy.start()
    t_forward.start()
    
    log.info("All monitoring and analysis modules are running. Monitoring for events...")
    
    # Keep main thread alive monitoring subprocess health
    while True:
        if suricata_proc.poll() is not None:
            log.critical("Suricata exited unexpectedly!")
            break
        if zeek_proc.poll() is not None:
            log.critical("Zeek Emulator exited unexpectedly!")
            break
        time.sleep(2)
        
    cleanup()
    sys.exit(1)

if __name__ == "__main__":
    main()
