"""
Always-On Security — Security Collector (Thread 4 in node agent)
Config tampering, lateral movement, process policy enforcement.
"""
import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

import psutil
import yaml

log = logging.getLogger("security_collector")

_POLICY_PATH   = os.getenv("PROCESS_POLICY_PATH", "/opt/security/config/process_policy.yaml")
_HASHES_PATH   = os.getenv("CONFIG_HASHES_PATH",  "/opt/security/config/config_hashes.yaml")
_DEFAULT_MONITOR_FILES = ["/etc/hosts", "/etc/passwd", "/etc/sudoers"]
_PEER_IPS_RAW  = os.getenv("NODE_PEER_IPS", "")
_SSH_PORT      = 22
_INTERVAL      = int(os.getenv("SECURITY_COLLECTOR_INTERVAL", "10"))


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _load_yaml_safe(path: str, default):
    try:
        with open(path) as f:
            return yaml.safe_load(f) or default
    except Exception as e:
        log.warning(f"Could not load {path}: {e}")
        return default


class SecurityCollector:
    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot: dict = {
            "config_tamper": False, "tampered_files": [],
            "unauthorized_procs": [], "ssh_connections": 0,
            "lateral_peers": [], "peer_contact_count": 0,
        }
        self._peer_ips = set(ip.strip() for ip in _PEER_IPS_RAW.split(",") if ip.strip())

    def get_snapshot(self) -> dict:
        with self._lock:
            return dict(self._snapshot)

    def run(self):
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

    def _check_config_tampering(self) -> dict:
        baselines = _load_yaml_safe(_HASHES_PATH, {})
        tampered = []
        for fpath in _DEFAULT_MONITOR_FILES:
            current = _sha256_file(fpath)
            if current is None:
                continue
            expected = baselines.get(fpath)
            if not expected:
                continue
            if current != expected:
                tampered.append({"file": fpath, "expected": expected, "actual": current})
        return {"config_tamper": len(tampered) > 0, "tampered_files": tampered}

    def _check_lateral_movement(self) -> dict:
        ssh_conns, lateral_peers = 0, set()
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                    continue
                rip, rport = conn.raddr.ip, conn.raddr.port
                lport = conn.laddr.port if conn.laddr else 0
                if rip in self._peer_ips and (rport == _SSH_PORT or lport == _SSH_PORT):
                    ssh_conns += 1
                    lateral_peers.add(rip)
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception as e:
            log.error(f"Lateral movement check error: {e}")
        return {"ssh_connections": ssh_conns, "lateral_peers": list(lateral_peers), "peer_contact_count": len(lateral_peers)}

    def _check_process_policy(self) -> dict:
        policy   = _load_yaml_safe(_POLICY_PATH, {"mode": "denylist", "denylist": [], "allowlist": []})
        mode     = policy.get("mode", "denylist").lower()
        denylist = {p.lower() for p in (policy.get("denylist") or [])}
        allowlist= {p.lower() for p in (policy.get("allowlist") or [])}
        unauthorized = []
        try:
            for proc in psutil.process_iter(["name", "pid"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    if not pname:
                        continue
                    if mode == "denylist" and pname in denylist:
                        unauthorized.append({"name": pname, "pid": proc.info.get("pid")})
                    elif mode == "allowlist" and allowlist and pname not in allowlist:
                        unauthorized.append({"name": pname, "pid": proc.info.get("pid")})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            log.error(f"Process policy check error: {e}")
        return {"unauthorized_procs": unauthorized}
