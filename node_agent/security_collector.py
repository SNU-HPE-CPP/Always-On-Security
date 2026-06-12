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
import ipaddress
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
_ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "/opt/security/config/allowlist.yaml")

# Files to monitor for tampering (can be extended via env var CSV)
_DEFAULT_MONITOR_FILES = ["/etc/hosts", "/etc/passwd", "/etc/sudoers"]
_EXTRA_MONITOR = os.getenv("MONITOR_FILES", "")

# Peer node IPs for lateral movement baselining (comma-separated env var)
_PEER_IPS_RAW = os.getenv("NODE_PEER_IPS", "")

# SSH port
_SSH_PORT = 22

# Network detection defaults for an isolated cluster.
_NETWORK_CLUSTER_CIDR = os.getenv("NETWORK_CLUSTER_CIDR", "172.20.0.0/16")
_NETWORK_ALLOWED_PORTS = os.getenv("NETWORK_ALLOWED_PORTS", "22,514,5555,5556")
_NETWORK_ALLOWED_LISTEN_PORTS = os.getenv("NETWORK_ALLOWED_LISTEN_PORTS", "5556")
_NETWORK_MAX_REMOTE_TARGETS = int(os.getenv("NETWORK_MAX_REMOTE_TARGETS", "8"))

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


def _parse_int_csv(raw: str) -> set[int]:
    values = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            values.add(int(item))
        except ValueError:
            log.warning(f"Ignoring invalid port entry: {item}")
    return values


def _parse_networks(raw: str) -> tuple:
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.warning(f"Ignoring invalid network CIDR: {item}")
    return tuple(networks)


def _ip_in_networks(ip: str, networks: tuple) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


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
            "network_threat":       False,
            "network_anomalies":    [],
            "unexpected_listeners": [],
            "unexpected_egress":    [],
            "remote_connection_count": 0,
            "remote_target_count":  0,
        }
        self._peer_ips = set(
            ip.strip() for ip in _PEER_IPS_RAW.split(",") if ip.strip()
        )
        allowlist_cfg = _load_yaml_safe(_ALLOWLIST_PATH, {})
        network_cfg = allowlist_cfg.get("network_detection", {}) if isinstance(allowlist_cfg, dict) else {}

        cluster_cidr = os.getenv(
            "NETWORK_CLUSTER_CIDR",
            str(network_cfg.get("cluster_cidr", _NETWORK_CLUSTER_CIDR)),
        )
        allowed_remote_ports = os.getenv(
            "NETWORK_ALLOWED_PORTS",
            ",".join(str(p) for p in network_cfg.get("allowed_remote_ports", [])) or _NETWORK_ALLOWED_PORTS,
        )
        allowed_listen_ports = os.getenv(
            "NETWORK_ALLOWED_LISTEN_PORTS",
            ",".join(str(p) for p in network_cfg.get("allowed_listen_ports", [])) or _NETWORK_ALLOWED_LISTEN_PORTS,
        )
        max_remote_targets = os.getenv(
            "NETWORK_MAX_REMOTE_TARGETS",
            str(network_cfg.get("max_remote_targets", _NETWORK_MAX_REMOTE_TARGETS)),
        )

        self._cluster_networks = _parse_networks(cluster_cidr)
        self._allowed_remote_ports = _parse_int_csv(allowed_remote_ports)
        self._allowed_listen_ports = _parse_int_csv(allowed_listen_ports)
        try:
            self._max_remote_targets = int(max_remote_targets)
        except ValueError:
            self._max_remote_targets = _NETWORK_MAX_REMOTE_TARGETS
        log.info(
            f"SecurityCollector init | peers={self._peer_ips} | "
            f"interval={_INTERVAL}s | cluster={cluster_cidr}"
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
                snapshot.update(self._check_network_threats())
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

    # ── C: Network Threats ────────────────────────

    def _check_network_threats(self) -> dict:
        """
        Detect suspicious TCP patterns for cluster nodes.

        The collector treats any TCP egress outside the cluster CIDR or any
        connection to a non-allowed port as suspicious. It also flags
        unexpected listeners and unusual fan-out across many remote targets.
        """
        anomalies = []
        unexpected_listeners = []
        unexpected_egress = []
        remote_targets = set()
        remote_connections = 0

        try:
            for conn in psutil.net_connections(kind="tcp"):
                laddr = conn.laddr
                raddr = conn.raddr
                local_port = laddr.port if laddr else 0

                if conn.status == psutil.CONN_LISTEN:
                    if local_port and local_port not in self._allowed_listen_ports:
                        unexpected_listeners.append({
                            "local_port": local_port,
                            "process_pid": conn.pid,
                            "status": conn.status,
                        })
                        anomalies.append(
                            f"unexpected listening port {local_port} (pid={conn.pid})"
                        )
                    continue

                if conn.status != psutil.CONN_ESTABLISHED or not raddr:
                    continue

                remote_connections += 1
                remote_ip = raddr.ip
                remote_port = raddr.port
                remote_targets.add(f"{remote_ip}:{remote_port}")

                try:
                    address = ipaddress.ip_address(remote_ip)
                except ValueError:
                    address = None

                in_cluster = _ip_in_networks(remote_ip, self._cluster_networks)
                allowed_port = remote_port in self._allowed_remote_ports
                is_loopback = bool(address and address.is_loopback)

                if not is_loopback and (not in_cluster or not allowed_port):
                    unexpected_egress.append({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "status": conn.status,
                        "pid": conn.pid,
                    })

                    if not in_cluster:
                        anomalies.append(
                            f"unexpected outbound connection to {remote_ip}:{remote_port}"
                        )
                    elif not allowed_port:
                        anomalies.append(
                            f"connection to disallowed port {remote_port} on {remote_ip}"
                        )

        except (psutil.AccessDenied, PermissionError):
            log.debug("net_connections: access denied while checking network threats.")
        except Exception as e:
            log.error(f"Network threat check error: {e}")

        if len(remote_targets) > self._max_remote_targets:
            anomalies.append(
                f"high TCP fan-out to {len(remote_targets)} remote targets"
            )

        network_threat = bool(anomalies)
        if network_threat:
            log.warning(f"NETWORK_THREAT detected: {anomalies}")

        return {
            "network_threat": network_threat,
            "network_anomalies": anomalies,
            "unexpected_listeners": unexpected_listeners,
            "unexpected_egress": unexpected_egress,
            "remote_connection_count": remote_connections,
            "remote_target_count": len(remote_targets),
        }

    # ── D: Process Policy ─────────────────────────

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
