#!/usr/bin/env python3
"""
Always-On Security — Pre-flight Configuration Integrity Check
NIST SP 800-234: CM-2 (Baseline Configuration), CM-6 (Configuration Settings),
                 SI-7(1) (Software/Firmware Integrity — startup check)

REC-08: Before any security service starts processing, verify that all YAML
config files match their expected SHA-256 hashes from the signed manifest
(config_hashes.yaml).  If ANY mismatch is found, print a CRITICAL error and
exit with code 2 so the container is never marked healthy.

Usage (called automatically from entrypoint.sh):
    python3 check_config_integrity.py --manifest /opt/security/config/config_hashes.yaml \
                                      --config-dir /opt/security/config

Exit codes:
    0  — All verified, safe to start
    1  — Manifest missing or unreadable (block startup)
    2  — One or more config files have been tampered (block startup)
    3  — Fatal unexpected error
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] check_config_integrity: %(message)s",
)
log = logging.getLogger("check_config_integrity")

# ── Constants ─────────────────────────────────────────────────────────────────

# Config files that MUST be verified before the service starts.
# These are the service-level YAML configs (not monitored host files like /etc/hosts).
# FIX #4: Removed process_policy.yaml — file does not exist in this deployment.
SERVICE_CONFIG_FILES = [
    "rules.yaml",
    "master_config.yaml",
]

# ANSI colour codes (used only when stdout is a tty)
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _c(code: str, text: str) -> str:
    """Apply ANSI colour only when writing to a real terminal."""
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


# ── Core helpers ──────────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str | None:
    """Return SHA-256 hex digest of *path*, or None if the file cannot be read."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65_536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        log.error("Cannot read %s: %s", path, exc)
        return None


def _load_manifest(manifest_path: Path) -> dict[str, str]:
    """
    Load the YAML hash manifest produced by generate_baseline.py.
    Returns a mapping of {file_path_or_name: sha256_hex}.
    Exits with code 1 if the manifest cannot be read or parsed.
    """
    if not manifest_path.exists():
        log.critical(
            "MANIFEST MISSING: %s — cannot verify config integrity. "
            "Run generate_baseline.py to create the manifest before deployment.",
            manifest_path,
        )
        sys.exit(1)

    try:
        with manifest_path.open() as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        log.critical("Cannot parse manifest %s: %s", manifest_path, exc)
        sys.exit(1)

    if not isinstance(data, dict):
        log.critical(
            "Manifest %s is malformed (expected a YAML mapping, got %s).",
            manifest_path,
            type(data).__name__,
        )
        sys.exit(1)

    return {str(k): str(v) for k, v in data.items() if v}


def _resolve_manifest_key(filename: str, manifest: dict[str, str], config_dir: Path) -> str | None:
    """
    The manifest may store keys as:
      - bare filenames:      "rules.yaml"
      - absolute paths:      "/opt/security/config/rules.yaml"
      - relative paths:      "config/rules.yaml"

    Try all three forms and return the matching key, or None.
    """
    candidates = [
        filename,
        str(config_dir / filename),
        str(Path(filename).name),
    ]
    for c in candidates:
        if c in manifest:
            return c
    return None


# ── Main verification logic ───────────────────────────────────────────────────

def verify_configs(
    manifest_path: Path,
    config_dir: Path,
    extra_files: list[str],
    strict: bool,
) -> int:
    """
    Verify all service config files against the manifest.

    Returns the number of tampered/missing files detected.
    """
    manifest = _load_manifest(manifest_path)

    files_to_check = list(SERVICE_CONFIG_FILES) + extra_files

    # De-duplicate while preserving order
    seen: set[str] = set()
    unique_files: list[str] = []
    for f in files_to_check:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    log.info(
        "Starting pre-flight integrity check | manifest=%s | config_dir=%s | files=%d",
        manifest_path,
        config_dir,
        len(unique_files),
    )

    node_name = os.getenv("NODE_NAME", os.getenv("HOSTNAME", "unknown"))
    service   = os.getenv("SERVICE_NAME", "unknown-service")

    results: list[dict] = []
    tampered_count  = 0
    missing_count   = 0
    no_baseline_count = 0

    print()
    print(_c(_BOLD, f"  ╔══ Pre-Flight Config Integrity Check ══"))
    print(_c(_BOLD, f"  ║  Service  : {service}"))
    print(_c(_BOLD, f"  ║  Node     : {node_name}"))
    print(_c(_BOLD, f"  ║  Manifest : {manifest_path}"))
    print(_c(_BOLD, f"  ║  Config   : {config_dir}"))
    print(_c(_BOLD, f"  ╠{'═' * 44}"))

    for filename in unique_files:
        file_path = config_dir / filename

        # Resolve expected hash from manifest
        manifest_key = _resolve_manifest_key(filename, manifest, config_dir)
        expected_hash = manifest.get(manifest_key) if manifest_key else None

        if not file_path.exists():
            status = "MISSING"
            missing_count += 1
            results.append({
                "file": filename,
                "status": status,
                "expected": expected_hash,
                "actual": None,
            })
            print(_c(_RED, f"  ║  ✗ MISSING  {filename}"))
            log.critical(
                "[CONFIG_INTEGRITY] MISSING: %s not found at %s",
                filename, file_path,
            )
            continue

        actual_hash = _sha256_file(file_path)

        if actual_hash is None:
            status = "UNREADABLE"
            missing_count += 1
            results.append({
                "file": filename,
                "status": status,
                "expected": expected_hash,
                "actual": None,
            })
            print(_c(_RED, f"  ║  ✗ UNREADABLE {filename}"))
            log.critical(
                "[CONFIG_INTEGRITY] UNREADABLE: cannot hash %s", file_path
            )
            continue

        if expected_hash is None:
            # No baseline entry yet — warn but don't block (unless --strict)
            status = "NO_BASELINE"
            no_baseline_count += 1
            results.append({
                "file": filename,
                "status": status,
                "expected": None,
                "actual": actual_hash,
            })
            if strict:
                print(_c(_RED, f"  ║  ✗ NO_BASELINE {filename} (strict mode — blocking)"))
                tampered_count += 1
                log.critical(
                    "[CONFIG_INTEGRITY] NO_BASELINE (strict): %s has no manifest entry. "
                    "Run generate_baseline.py to add it.",
                    filename,
                )
            else:
                print(_c(_YELLOW, f"  ║  ? NO_BASELINE {filename} (warn only — add to manifest)"))
                log.warning(
                    "[CONFIG_INTEGRITY] NO_BASELINE: %s has no manifest entry — skipping. "
                    "Run generate_baseline.py to register it.",
                    filename,
                )
            continue

        if actual_hash == expected_hash:
            status = "OK"
            results.append({
                "file": filename,
                "status": status,
                "expected": expected_hash,
                "actual": actual_hash,
            })
            print(_c(_GREEN, f"  ║  ✓ OK        {filename}  [{actual_hash[:16]}…]"))
            log.info("[CONFIG_INTEGRITY] OK: %s", filename)
        else:
            status = "TAMPERED"
            tampered_count += 1
            results.append({
                "file": filename,
                "status": status,
                "expected": expected_hash,
                "actual": actual_hash,
            })
            print(_c(_RED,
                f"  ║  ✗ TAMPERED  {filename}\n"
                f"  ║    expected: {expected_hash}\n"
                f"  ║    actual  : {actual_hash}"
            ))
            log.critical(
                "[CONFIG_INTEGRITY] TAMPERED: %s — expected=%s got=%s",
                filename, expected_hash[:16], actual_hash[:16],
            )

    # ── Summary ────────────────────────────────────────────────────────────────
    total     = len(unique_files)
    ok_count  = sum(1 for r in results if r["status"] == "OK")
    failed    = tampered_count + missing_count

    print(_c(_BOLD, f"  ╠{'═' * 44}"))
    if failed == 0:
        print(_c(_GREEN, f"  ║  RESULT: ALL {ok_count}/{total} CONFIG FILES VERIFIED ✓"))
    else:
        print(_c(_RED,
            f"  ║  RESULT: {failed} FILE(S) FAILED INTEGRITY CHECK ✗\n"
            f"  ║          Tampered={tampered_count}  Missing={missing_count}  "
            f"No-baseline={no_baseline_count}\n"
            f"  ║\n"
            f"  ║  ⛔  SERVICE STARTUP BLOCKED — NIST SI-7 / CM-6\n"
            f"  ║  ⛔  Restore config from a trusted source before restarting."
        ))
    print(_c(_BOLD, f"  ╚{'═' * 44}"))
    print()

    # ── Write machine-readable audit record ───────────────────────────────────
    audit_dir = Path(os.getenv("INTEGRITY_AUDIT_DIR", "/data/integrity_audits"))
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
        ts_safe = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        audit_file = audit_dir / f"{service}_{node_name}_{ts_safe}.json"
        audit_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": service,
            "node": node_name,
            "manifest": str(manifest_path),
            "config_dir": str(config_dir),
            "total_files": total,
            "ok": ok_count,
            "tampered": tampered_count,
            "missing": missing_count,
            "no_baseline": no_baseline_count,
            "passed": failed == 0,
            "results": results,
        }
        audit_file.write_text(json.dumps(audit_record, indent=2))
        log.info("Integrity audit record written to %s", audit_file)
    except Exception as exc:
        log.warning("Could not write integrity audit record: %s", exc)

    return failed


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "REC-08 Pre-flight Config Integrity Check (NIST CM-2 / CM-6 / SI-7). "
            "Verifies all service YAML configs against their SHA-256 manifest before startup."
        )
    )
    parser.add_argument(
        "--manifest",
        default=os.getenv("CONFIG_HASHES_PATH", "/opt/security/config/config_hashes.yaml"),
        help="Path to the SHA-256 hash manifest (config_hashes.yaml). "
             "Default: $CONFIG_HASHES_PATH or /opt/security/config/config_hashes.yaml",
    )
    parser.add_argument(
        "--config-dir",
        default=os.getenv("CONFIG_DIR", "/opt/security/config"),
        help="Directory containing the YAML config files to verify. "
             "Default: $CONFIG_DIR or /opt/security/config",
    )
    parser.add_argument(
        "--extra-files",
        default="",
        help="Comma-separated list of additional filenames (relative to --config-dir) to verify.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=os.getenv("INTEGRITY_STRICT", "").lower() in ("1", "true", "yes"),
        help="Treat files with no manifest entry as tampered (block startup). "
             "Default: warn only. Set INTEGRITY_STRICT=true to enable.",
    )
    parser.add_argument(
        "--allow-missing-manifest",
        action="store_true",
        default=os.getenv("INTEGRITY_ALLOW_MISSING_MANIFEST", "").lower() in ("1", "true", "yes"),
        help="If set, a missing manifest is treated as a warning (not a fatal error). "
             "Useful during initial deployment before the first baseline is generated. "
             "Set INTEGRITY_ALLOW_MISSING_MANIFEST=true to enable.",
    )

    args = parser.parse_args()
    manifest_path = Path(args.manifest)
    config_dir    = Path(args.config_dir)

    # ── Guard: allow-missing-manifest mode ───────────────────────────────────
    if not manifest_path.exists() and args.allow_missing_manifest:
        log.warning(
            "Manifest not found at %s and --allow-missing-manifest is set. "
            "Skipping integrity check — generate a baseline before production use.",
            manifest_path,
        )
        print(_c(_YELLOW,
            "\n  ⚠  Manifest not found — integrity check skipped (allow-missing-manifest mode).\n"
            "     Run generate_baseline.py to create a manifest before next deployment.\n"
        ))
        return 0

    extra_files = [
        f.strip() for f in args.extra_files.split(",") if f.strip()
    ]

    try:
        failed = verify_configs(
            manifest_path=manifest_path,
            config_dir=config_dir,
            extra_files=extra_files,
            strict=args.strict,
        )
    except Exception as exc:
        log.critical("Unexpected error during integrity check: %s", exc, exc_info=True)
        return 3

    return 2 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
