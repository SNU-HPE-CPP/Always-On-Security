"""
Always-On Security — Host Observer (cluster_observer.py)

Infrastructure-Zone observer. Monitors tenant containers externally via the
Docker Daemon API. Three detection subsystems:

  1. Resource Telemetry        — CPU / memory stats via Docker stats API
  2. Image Attestation         — validates running image digests against
                                 approved_images.yaml; no container access
  3. Runtime Drift Detection   — compares live container runtime config
                                 against runtime_baseline.yaml; detects
                                 unexpected caps, volumes, networks, users
  4. Infra Config Integrity    — periodically hashes infrastructure-owned
                                 YAML config files; alerts on CONFIG_DRIFT /
                                 POLICY_TAMPER / ALLOWLIST_TAMPER

Design constraints:
  - No commands are executed inside tenant containers.
  - No files are read from inside tenant containers.
  - No tenant-owned files are hashed.
  - FIM and process denylist detection have been intentionally removed.
    Production HPC providers do not hash customer files, and process
    names are trivially spoofable.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
import logging
import yaml
import docker
import zmq

from secure_messenger import SecureMessenger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cluster_observer")

CONFIG_DIR      = "/opt/security/config"
CONTROLLER_URL  = os.getenv("CONTROLLER_URL", "tcp://controller:5555")

# Infrastructure-owned config files monitored for tampering.
# These are security policy files, NOT tenant-owned customer files.
INFRA_CONFIG_FILES = [
    os.path.join(CONFIG_DIR, "rules.yaml"),
    os.path.join(CONFIG_DIR, "master_config.yaml"),
    os.path.join(CONFIG_DIR, "fast_path_policy.yaml"),
    os.path.join(CONFIG_DIR, "approved_images.yaml"),
    os.path.join(CONFIG_DIR, "runtime_baseline.yaml"),
]

# Map config file basename to the alert threat_type it generates
INFRA_FILE_THREAT_TYPE = {
    "rules.yaml":          "POLICY_TAMPER",
    "master_config.yaml":  "ALLOWLIST_TAMPER",
    "fast_path_policy.yaml": "POLICY_TAMPER",
    "approved_images.yaml":  "POLICY_TAMPER",
    "runtime_baseline.yaml": "POLICY_TAMPER",
}

INFRA_INTEGRITY_INTERVAL = 30  # seconds between infra config hash checks


# ─────────────────────────────────────────────────────────────────────────────
# Config loaders
# ─────────────────────────────────────────────────────────────────────────────

def load_allowlist() -> list[str]:
    path = os.getenv("ALLOWLIST_PATH", os.path.join(CONFIG_DIR, "master_config.yaml"))
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
            return data.get("allowed_nodes", ["node1", "node2", "node3", "node4"])
    except Exception as e:
        log.error(f"Error loading allowlist from {path}: {e}")
        return ["node1", "node2", "node3", "node4"]


def load_approved_images() -> dict[str, str]:
    """
    Returns {container_name: expected_digest} from approved_images.yaml.
    Digest format: 'sha256:<hex>'
    """
    path = os.path.join(CONFIG_DIR, "approved_images.yaml")
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
            return data.get("approved_images", {})
    except FileNotFoundError:
        log.warning("approved_images.yaml not found — image attestation disabled")
        return {}
    except Exception as e:
        log.error(f"Error loading approved_images.yaml: {e}")
        return {}


def load_runtime_baseline() -> dict[str, dict]:
    """
    Returns {container_name: {user, capabilities, volumes, networks,
                               restart_policy, image_digest, security_opts}}
    """
    path = os.path.join(CONFIG_DIR, "runtime_baseline.yaml")
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
            return data.get("baseline", {})
    except FileNotFoundError:
        log.warning("runtime_baseline.yaml not found — runtime drift detection disabled")
        return {}
    except Exception as e:
        log.error(f"Error loading runtime_baseline.yaml: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Docker stat helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_container_stats(container) -> tuple[float, float]:
    """Calculate CPU and Memory usage percentages from container stats."""
    try:
        stats = container.stats(stream=False)
        cpu_stats   = stats.get("cpu_stats", {})
        precpu      = stats.get("precpu_stats", {})
        cpu_delta   = (cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
                       - precpu.get("cpu_usage", {}).get("total_usage", 0))
        sys_delta   = (cpu_stats.get("system_cpu_usage", 0)
                       - precpu.get("system_cpu_usage", 0))
        cpu_pct     = 0.0
        if sys_delta > 0 and cpu_delta > 0:
            ncpus   = (cpu_stats.get("online_cpus")
                       or len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", [])) or 1)
            cpu_pct = (cpu_delta / sys_delta) * ncpus * 100.0

        mem_stats = stats.get("memory_stats", {})
        mem_usage = mem_stats.get("usage", 0)
        cache     = mem_stats.get("stats", {}).get("inactive_file", 0)
        active    = max(0, mem_usage - cache)
        mem_limit = mem_stats.get("limit", 1) or 1
        mem_pct   = (active / mem_limit) * 100.0
        return min(100.0, cpu_pct), min(100.0, mem_pct)
    except Exception as e:
        log.debug(f"Failed to fetch stats for {container.name}: {e}")
        return 0.0, 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Improvement 1 — Image Attestation
# ─────────────────────────────────────────────────────────────────────────────

def check_image_attestation(
    container,
    approved: dict[str, str],
) -> list[dict]:
    """
    Compare the running container's image digest against approved_images.yaml.
    Returns a list of drift events (empty = clean).

    All information comes from Docker inspect — no exec inside container.
    """
    events = []
    node = container.name

    # Reload to get fresh attrs
    container.reload()
    attrs = container.attrs

    # 60-second grace period for newly started containers
    started_at_str = attrs.get("State", {}).get("StartedAt")
    if started_at_str:
        try:
            import datetime
            import re
            # Clean up the string to match python's fromisoformat limitations
            ts_str = re.sub(r'\.\d+Z$', 'Z', started_at_str).replace('Z', '+00:00')
            started_at = datetime.datetime.fromisoformat(ts_str)
            if (datetime.datetime.now(datetime.timezone.utc) - started_at).total_seconds() < 60:
                # Still in grace period, return no drift
                return []
        except Exception as e:
            log.debug(f"Failed to parse StartedAt for {node}: {e}")

    # Extract running image digest
    image_id     = attrs.get("Image", "")         # sha256:... of image layer
    image_name   = attrs.get("Config", {}).get("Image", "")
    repo_digests = []

    try:
        img = container.client.images.get(image_id)
        repo_digests = img.attrs.get("RepoDigests", [])
    except Exception:
        pass

    running_digest = image_id  # fallback to image ID
    if repo_digests:
        # Prefer full repo digest (includes registry)
        running_digest = repo_digests[0]

    if node not in approved:
        events.append({
            "event_type":   "UNAPPROVED_IMAGE",
            "reasons":      [f"Node {node} has no approved image digest in policy"],
            "evidence": {
                "node":           node,
                "running_digest": running_digest,
                "image_name":     image_name,
                "image_id":       image_id,
            },
        })
        return events

    expected_digest = approved[node]
    # Compare: support both full digest and bare sha256:... ID
    digest_ok = (
        running_digest == expected_digest
        or image_id == expected_digest
        or any(expected_digest in rd for rd in repo_digests)
    )

    if not digest_ok:
        log.warning(
            f"[IMAGE_MISMATCH] node={node} "
            f"expected={expected_digest[:20]}... "
            f"running={running_digest[:20]}..."
        )
        events.append({
            "event_type": "IMAGE_MISMATCH",
            "reasons":    [f"Image digest mismatch for {node}"],
            "evidence": {
                "node":             node,
                "expected_digest":  expected_digest,
                "running_digest":   running_digest,
                "image_name":       image_name,
                "image_id":         image_id,
                "repo_digests":     repo_digests,
            },
        })

    return events


# ─────────────────────────────────────────────────────────────────────────────
# Improvement 2 — Runtime Drift Detection
# ─────────────────────────────────────────────────────────────────────────────

def _extract_runtime_state(container) -> dict:
    """
    Pull runtime configuration from Docker inspect without entering container.
    Returns a dict of security-relevant fields.
    """
    container.reload()
    attrs = container.attrs
    host_cfg  = attrs.get("HostConfig", {})
    cfg       = attrs.get("Config", {})
    net_cfg   = attrs.get("NetworkSettings", {}).get("Networks", {})

    # Capabilities
    cap_add  = sorted(host_cfg.get("CapAdd") or [])
    cap_drop = sorted(host_cfg.get("CapDrop") or [])

    # Volume mounts (bind mounts only, not named volumes — those are expected)
    binds = []
    for m in (host_cfg.get("Binds") or []):
        binds.append(m)

    # Attached networks
    networks = sorted(net_cfg.keys())

    # Restart policy
    rp = host_cfg.get("RestartPolicy", {})
    restart_policy = f"{rp.get('Name', 'no')}:{rp.get('MaximumRetryCount', 0)}"

    # Running user
    user = cfg.get("User", "")

    # Security options (no-new-privileges, apparmor, seccomp)
    security_opts = sorted(host_cfg.get("SecurityOpt") or [])

    # Image digest (already pulled in attestation, include here for completeness)
    image_id = attrs.get("Image", "")

    return {
        "user":          user,
        "cap_add":       cap_add,
        "cap_drop":      cap_drop,
        "binds":         binds,
        "networks":      networks,
        "restart_policy": restart_policy,
        "security_opts": security_opts,
        "image_id":      image_id,
    }


def check_runtime_drift(
    container,
    baseline: dict[str, dict],
) -> list[dict]:
    """
    Compare live runtime state against runtime_baseline.yaml.
    Returns drift events (empty = no drift).
    """
    events = []
    node = container.name

    if node not in baseline:
        # No baseline registered — cannot detect drift
        return events

    expected = baseline[node]
    actual   = _extract_runtime_state(container)

    drifts = []

    # User check
    exp_user = expected.get("user", "")
    if exp_user and actual["user"] != exp_user:
        drifts.append({
            "field":    "user",
            "expected": exp_user,
            "actual":   actual["user"],
            "detail":   f"Container running as '{actual['user']}', expected '{exp_user}'",
        })

    # Capability check
    exp_caps = sorted(expected.get("cap_add", []))
    if actual["cap_add"] != exp_caps:
        drifts.append({
            "field":    "cap_add",
            "expected": exp_caps,
            "actual":   actual["cap_add"],
            "detail":   f"Unexpected capabilities: added={actual['cap_add']}, expected={exp_caps}",
        })

    # Bind mounts check
    exp_binds = sorted(expected.get("binds", []))
    if sorted(actual["binds"]) != exp_binds:
        drifts.append({
            "field":    "binds",
            "expected": exp_binds,
            "actual":   actual["binds"],
            "detail":   "Unexpected bind mount(s) detected",
        })

    # Network check
    exp_nets = sorted(expected.get("networks", []))
    if actual["networks"] != exp_nets:
        drifts.append({
            "field":    "networks",
            "expected": exp_nets,
            "actual":   actual["networks"],
            "detail":   f"Unexpected network attachment: {actual['networks']} vs {exp_nets}",
        })

    # Restart policy check
    exp_rp = expected.get("restart_policy", "no:0")
    if actual["restart_policy"] != exp_rp:
        drifts.append({
            "field":    "restart_policy",
            "expected": exp_rp,
            "actual":   actual["restart_policy"],
            "detail":   f"Restart policy changed: {actual['restart_policy']} vs {exp_rp}",
        })

    # Security opts check
    exp_opts = sorted(expected.get("security_opts", []))
    if actual["security_opts"] != exp_opts:
        drifts.append({
            "field":    "security_opts",
            "expected": exp_opts,
            "actual":   actual["security_opts"],
            "detail":   "Security options changed",
        })

    if drifts:
        log.warning(f"[RUNTIME_DRIFT] node={node} drifts={[d['field'] for d in drifts]}")
        events.append({
            "event_type": "RUNTIME_DRIFT",
            "reasons":    [f"Runtime drift detected for {node}: {[d['detail'] for d in drifts]}"],
            "evidence": {
                "node":    node,
                "drifts":  drifts,
                "actual":  actual,
            },
        })

    return events


# ─────────────────────────────────────────────────────────────────────────────
# Improvement 3 — Infrastructure Configuration Integrity
# ─────────────────────────────────────────────────────────────────────────────

def _sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class InfraConfigGuard:
    """
    Compares SHA-256 hashes of infrastructure-owned config files against
    the signed manifest (config_hashes.yaml) rather than a freshly-captured
    startup snapshot.

    FIX #15: The old implementation called _capture_baseline() at startup,
    which accepted whatever state the files were in at that moment — including
    already-tampered files.  The correct anchor is config_hashes.yaml, which
    was generated from a known-good state and committed to version control.
    Files not listed in the manifest still get a startup snapshot as fallback.
    """

    def __init__(self, paths: list[str], manifest_path: str = None):
        self._paths    = paths
        self._last_check = 0.0
        # Load trusted hashes from the manifest (config_hashes.yaml)
        self._manifest: dict[str, str] = {}
        self._startup: dict[str, str]  = {}  # fallback for unlisted files
        _mpath = manifest_path or os.path.join(CONFIG_DIR, "config_hashes.yaml")
        self._load_manifest(_mpath)
        self._capture_startup_fallback()

    def _load_manifest(self, manifest_path: str) -> None:
        try:
            with open(manifest_path) as f:
                data = yaml.safe_load(f) or {}
            self._manifest = {str(k): str(v) for k, v in data.items() if v}
            log.info(
                f"[InfraConfig] Loaded manifest with {len(self._manifest)} entries "
                f"from {manifest_path}"
            )
        except FileNotFoundError:
            log.warning(
                f"[InfraConfig] Manifest not found at {manifest_path} — "
                "falling back to startup-snapshot baseline"
            )
        except Exception as e:
            log.warning(f"[InfraConfig] Could not read manifest: {e}")

    def _resolve_expected(self, path: str) -> str | None:
        """Try bare filename, absolute path, and relative path against manifest."""
        basename = os.path.basename(path)
        for key in (path, basename, f"risk_engine/config/{basename}"):
            if key in self._manifest:
                return self._manifest[key]
        return None

    def _capture_startup_fallback(self) -> None:
        """Capture startup hashes only for files NOT covered by the manifest."""
        for path in self._paths:
            if self._resolve_expected(path) is None:
                digest = _sha256_file(path)
                if digest:
                    self._startup[path] = digest
                    log.warning(
                        f"[InfraConfig] {os.path.basename(path)} not in manifest — "
                        f"using startup snapshot as fallback"
                    )
                else:
                    log.warning(f"[InfraConfig] Cannot hash {path} — file may not exist yet")

    def check(self) -> list[dict]:
        """
        Returns a list of CONFIG_DRIFT / POLICY_TAMPER / ALLOWLIST_TAMPER events.
        Rate-limited to once per INFRA_INTEGRITY_INTERVAL seconds.
        """
        now = time.time()
        if now - self._last_check < INFRA_INTEGRITY_INTERVAL:
            return []
        self._last_check = now

        events = []
        for path in self._paths:
            expected = self._resolve_expected(path)
            # Fall back to startup snapshot for files not in the manifest
            if expected is None:
                expected = self._startup.get(path)
            if expected is None:
                # Try to capture if file appeared after startup
                digest = _sha256_file(path)
                if digest:
                    self._startup[path] = digest
                continue

            current = _sha256_file(path)
            if current is None:
                log.warning(f"[InfraConfig] File missing: {path}")
                continue

            if current != expected:
                basename    = os.path.basename(path)
                threat_type = INFRA_FILE_THREAT_TYPE.get(basename, "CONFIG_DRIFT")
                log.warning(
                    f"[{threat_type}] Infra config modified: {basename} "
                    f"expected={expected[:16]}... current={current[:16]}..."
                )
                events.append({
                    "event_type": threat_type,
                    "reasons":    [f"Infrastructure config modified: {basename}"],
                    "evidence": {
                        "path":             path,
                        "expected_digest":  expected,
                        "current_digest":   current,
                        "threat_type":      threat_type,
                    },
                })
                # Update startup snapshot to avoid repeated alerts for same change
                # (manifest entry remains unchanged — next restart will re-detect)
                self._startup[path] = current

        return events


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

def _send_event(sender: zmq.Socket, messenger: SecureMessenger, payload: dict) -> None:
    try:
        signed = messenger.sign(payload)
        sender.send_json(signed)
    except Exception as e:
        log.error(f"Failed to send event: {e}")


def main():
    log.info("Host/Cluster Observer starting up...")

    ctx    = zmq.Context()
    sender = ctx.socket(zmq.PUSH)
    sender.connect(CONTROLLER_URL)
    log.info(f"Connected to Controller at {CONTROLLER_URL}")

    try:
        client = docker.from_env()
        log.info("Connected to Docker daemon successfully.")
    except Exception as e:
        log.critical(f"Cannot connect to Docker daemon: {e}")
        sys.exit(1)

    # Per-node SecureMessenger instances (stable machine_id = container ID)
    messengers: dict[str, SecureMessenger] = {}

    # Infrastructure config integrity guard — anchored to config_hashes.yaml manifest
    infra_guard = InfraConfigGuard(
        INFRA_CONFIG_FILES,
        manifest_path=os.path.join(CONFIG_DIR, "config_hashes.yaml"),
    )

    log.info("Host Observer ready — starting monitoring loop")

    while True:
        try:
            nodes           = load_allowlist()
            approved_images = load_approved_images()
            runtime_base    = load_runtime_baseline()

            # ── Per-node checks ───────────────────────────────────────
            for node in nodes:
                try:
                    container = client.containers.get(node)
                    container.reload()

                    if container.status != "running":
                        log.debug(f"Node {node} not running (status={container.status})")
                        continue

                    cid = container.id
                    if node not in messengers:
                        messengers[node] = SecureMessenger(node_name=node, machine_id=cid)
                    messenger = messengers[node]

                    # 1. Resource telemetry
                    cpu, mem = get_container_stats(container)

                    # 2. Image Attestation
                    if node not in ("host-observer", "security-monitor", "alert-ingestor", "remediation-engine", "controller"):
                        image_events = check_image_attestation(container, approved_images)
                        for evt in image_events:
                            payload = {
                                "node":          node,
                                "cpu_usage":     round(cpu, 2),
                                "memory_usage":  round(mem, 2),
                                "process_count": 0,
                                "failed_login_count": 0,
                                "privilege_escalation_attempts": 0,
                                "is_busy":       False,
                                "active_job_type": None,
                                "event_type":    evt["event_type"],
                                "reasons":       evt["reasons"],
                                "evidence":      evt["evidence"],
                                "config_tamper": False,
                                "tampered_files": [],
                                "unauthorized_procs": [],
                            }
                            _send_event(sender, messenger, payload)
                            log.warning(f"Sent {evt['event_type']} for {node}")

                    # 3. Runtime Drift
                    drift_events = check_runtime_drift(container, runtime_base)
                    for evt in drift_events:
                        payload = {
                            "node":          node,
                            "cpu_usage":     round(cpu, 2),
                            "memory_usage":  round(mem, 2),
                            "process_count": 0,
                            "failed_login_count": 0,
                            "privilege_escalation_attempts": 0,
                            "is_busy":       False,
                            "active_job_type": None,
                            "event_type":    evt["event_type"],
                            "reasons":       evt["reasons"],
                            "evidence":      evt["evidence"],
                            "config_tamper": False,
                            "tampered_files": [],
                            "unauthorized_procs": [],
                        }
                        _send_event(sender, messenger, payload)
                        log.warning(f"Sent {evt['event_type']} for {node}")

                    # 4. Standard telemetry (always sent, even when no anomalies)
                    telemetry = {
                        "node":          node,
                        "cpu_usage":     round(cpu, 2),
                        "memory_usage":  round(mem, 2),
                        "process_count": 0,
                        "failed_login_count": 0,
                        "privilege_escalation_attempts": 0,
                        "is_busy":       False,
                        "active_job_type": None,
                        "event_type":    "NORMAL",
                        "reasons":       [],
                        "config_tamper": False,
                        "tampered_files": [],
                        "unauthorized_procs": [],
                    }
                    _send_event(sender, messenger, telemetry)
                    log.debug(f"Telemetry sent for {node} (cpu={cpu:.1f}% mem={mem:.1f}%)")

                except docker.errors.NotFound:
                    log.debug(f"Container {node} not found.")
                except Exception as e:
                    log.error(f"Error checking node {node}: {e}", exc_info=True)

            # ── Infrastructure Config Integrity (rate-limited internally) ──
            infra_events = infra_guard.check()
            for evt in infra_events:
                # Use a dedicated messenger for infrastructure alerts
                if "infra" not in messengers:
                    try:
                        host_cid = client.containers.get("host-observer").id
                    except:
                        host_cid = None
                    messengers["infra"] = SecureMessenger(node_name="host-observer", machine_id=host_cid)
                payload = {
                    "node":          "host-observer",
                    "cpu_usage":     0.0,
                    "memory_usage":  0.0,
                    "process_count": 0,
                    "failed_login_count": 0,
                    "privilege_escalation_attempts": 0,
                    "is_busy":       False,
                    "active_job_type": None,
                    "event_type":    evt["event_type"],
                    "reasons":       evt["reasons"],
                    "evidence":      evt["evidence"],
                    "config_tamper": True,
                    "tampered_files": [],
                    "unauthorized_procs": [],
                }
                _send_event(sender, messengers["infra"], payload)

        except Exception as e:
            log.error(f"Loop error in Host Observer: {e}")

        time.sleep(5)


if __name__ == "__main__":
    main()
