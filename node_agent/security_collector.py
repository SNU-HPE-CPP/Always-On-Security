"""
Always-On Security — Security Collector (Thread 3 in node agent)

Collects security-specific telemetry beyond hardware metrics:
  A. Config Tampering Detection  — SHA-256 hashes of monitored config files
  B. Lateral Movement Detection  — Monitors active TCP connections to peer nodes
  C. Unauthorized Process Check  — Enforces process allowlist / denylist policy

Each cycle pushes a security_event dict onto a thread-safe queue;
the main telemetry thread merges this into the ZMQ payload.
"""

import hashlib
import json
import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Optional

import psutil
import yaml

log = logging.getLogger("security_collector")

# ─────────────────────────────────────────
# Configuration paths (mounted as read-only)
# ─────────────────────────────────────────
_POLICY_PATH   = os.getenv("PROCESS_POLICY_PATH", "/opt/security/config/process_policy.yaml")
_HASHES_PATH   = os.getenv("CONFIG_HASHES_PATH",  "/opt/security/config/config_hashes.yaml")

# Files to monitor for tampering (can be extended via env var CSV)
_DEFAULT_MONITOR_FILES = ["/etc/hosts", "/etc/passwd", "/etc/sudoers"]
_EXTRA_MONITOR = os.getenv("MONITOR_FILES", "")

# Peer node IPs for lateral movement baselining (comma-separated env var)
_PEER_IPS_RAW = os.getenv("NODE_PEER_IPS", "")

# SSH port
_SSH_PORT = 22

# Collection interval (seconds)
_INTERVAL = int(os.getenv("SECURITY_COLLECTOR_INTERVAL", "10"))


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _sha256_file(path: str) -> Optional[str]:
    """Return SHA-256 hex digest of a file, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _load_yaml_safe(path: str, default):
    """Load a YAML file safely; return default on any error."""
    try:
        with open(path) as f:
            return yaml.safe_load(f) or default
    except Exception as e:
        log.warning(f"Could not load {path}: {e}")
        return default


# ─────────────────────────────────────────
# SecurityCollector
# ─────────────────────────────────────────

class SecurityCollector:
    """
    Runs as a daemon thread.  Collects security telemetry every _INTERVAL
    seconds and makes the latest snapshot available via get_snapshot().
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot: dict = {
            "config_tamper":        False,
            "tampered_files":       [],
            "unauthorized_procs":   [],
            "ssh_connections":      0,
            "lateral_peers":        [],
            "peer_contact_count":   0,
        }
        self._peer_ips = set(
            ip.strip() for ip in _PEER_IPS_RAW.split(",") if ip.strip()
        )
        log.info(
            f"SecurityCollector init | peers={self._peer_ips} | "
            f"interval={_INTERVAL}s"
        )

    # ── Public API ────────────────────────────────

    def get_snapshot(self) -> dict:
        """Return latest security snapshot (thread-safe copy)."""
        with self._lock:
            return dict(self._snapshot)

    def run(self):
        """Main collection loop — intended to run in a daemon thread."""
        log.info("SecurityCollector thread started.")
        while True:
            try:
                snapshot = {}
                snapshot.update(self._check_config_tampering())
                snapshot.update(self._check_lateral_movement())
                snapshot.update(self._check_process_policy())
                with self._lock:
                    self._snapshot = snapshot
            except Exception as e:
                log.error(f"SecurityCollector cycle error: {e}", exc_info=True)
            time.sleep(_INTERVAL)

    # ── A: Config Tampering ───────────────────────

    def _check_config_tampering(self) -> dict:
        monitor_files = list(_DEFAULT_MONITOR_FILES)
        if _EXTRA_MONITOR:
            monitor_files += [p.strip() for p in _EXTRA_MONITOR.split(",") if p.strip()]

        baselines = _load_yaml_safe(_HASHES_PATH, {})
        tampered = []

        for fpath in monitor_files:
            current_hash = _sha256_file(fpath)
            if current_hash is None:
                # File unreadable (may be normal inside container)
                continue
            expected = baselines.get(fpath)
            if not expected:
                # No baseline or empty placeholder — skip until baseline is generated.
                # Run generate_baseline.py to populate config_hashes.yaml.
                log.debug(f"No baseline hash for {fpath} — skipping tamper check.")
                continue
            if current_hash != expected:
                log.warning(
                    f"CONFIG_TAMPER detected: {fpath} "
                    f"(expected={expected[:12]}... got={current_hash[:12]}...)"
                )
                tampered.append({
                    "file":     fpath,
                    "expected": expected,
                    "actual":   current_hash,
                })

        return {
            "config_tamper":  len(tampered) > 0,
            "tampered_files": tampered,
        }

    # ── B: Lateral Movement ───────────────────────

    def _check_lateral_movement(self) -> dict:
        """
        Detect unexpected SSH connections to/from peer node IPs.
        Uses psutil.net_connections() — requires appropriate permissions.
        NOTE(security): This is best-effort inside a container.
        For production, replace with eBPF/auditd kernel-level monitoring.
        """
        ssh_conns = 0
        lateral_peers = set()

        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != psutil.CONN_ESTABLISHED:
                    continue
                laddr = conn.laddr
                raddr = conn.raddr

                if not raddr:
                    continue

                remote_ip   = raddr.ip
                remote_port = raddr.port
                local_port  = laddr.port if laddr else 0

                # Flag connections where SSH port is involved and remote IP
                # belongs to a known peer node
                if remote_ip in self._peer_ips and (
                    remote_port == _SSH_PORT or local_port == _SSH_PORT
                ):
                    ssh_conns += 1
                    lateral_peers.add(remote_ip)

        except (psutil.AccessDenied, PermissionError):
            # TODO(security): Switch to eBPF probe for unprivileged containers
            log.debug("net_connections: access denied (unprivileged container).")
        except Exception as e:
            log.error(f"Lateral movement check error: {e}")

        return {
            "ssh_connections":    ssh_conns,
            "lateral_peers":      list(lateral_peers),
            "peer_contact_count": len(lateral_peers),
        }

    # ── C: Process Policy ─────────────────────────

    def _check_process_policy(self) -> dict:
        """
        Enforce process allowlist or denylist based on process_policy.yaml.
        Returns list of unauthorized process names found.
        """
        policy = _load_yaml_safe(_POLICY_PATH, {"mode": "denylist", "denylist": [], "allowlist": []})
        mode      = policy.get("mode", "denylist").lower()
        denylist  = {p.lower() for p in (policy.get("denylist") or [])}
        allowlist = {p.lower() for p in (policy.get("allowlist") or [])}

        unauthorized = []
        try:
            for proc in psutil.process_iter(["name", "pid", "cmdline"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    if not pname:
                        continue

                    if mode == "denylist":
                        if pname in denylist:
                            unauthorized.append({
                                "name": pname,
                                "pid":  proc.info.get("pid"),
                            })
                    elif mode == "allowlist":
                        if allowlist and pname not in allowlist:
                            unauthorized.append({
                                "name": pname,
                                "pid":  proc.info.get("pid"),
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            log.error(f"Process policy check error: {e}")

        if unauthorized:
            log.warning(f"UNAUTH_PROCESS detected: {[p['name'] for p in unauthorized]}")

        return {"unauthorized_procs": unauthorized}
