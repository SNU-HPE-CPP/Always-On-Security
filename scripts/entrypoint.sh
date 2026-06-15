#!/bin/sh
# =============================================================================
# Always-On Security — Service Entrypoint with Pre-flight Integrity Check
# NIST SP 800-234: CM-2, CM-6, SI-7(1)
#
# REC-08: Before starting the real service, run check_config_integrity.py.
# If any config file has been tampered with, exit immediately and DO NOT start
# the service. The Docker health check will mark the container as unhealthy.
#
# Environment variables:
#   SERVICE_NAME                   — human-readable service label for audit records
#   CONFIG_HASHES_PATH             — path to SHA-256 manifest (default: /opt/security/config/config_hashes.yaml)
#   CONFIG_DIR                     — directory of YAML configs to verify (default: /opt/security/config)
#   INTEGRITY_STRICT               — set to "true" to block on missing manifest entries
#   INTEGRITY_ALLOW_MISSING_MANIFEST — set to "true" during initial deployment (before first baseline)
#   CMD                            — the actual command to run after check passes (set in Dockerfile)
# =============================================================================

set -e

MANIFEST="${CONFIG_HASHES_PATH:-/opt/security/config/config_hashes.yaml}"
CONFIG_DIR="${CONFIG_DIR:-/opt/security/config}"
SERVICE="${SERVICE_NAME:-$(basename "$0")}"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Always-On Security — Pre-flight Check"
echo "  Service : ${SERVICE}"
echo "  Time    : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "═══════════════════════════════════════════════════════"

# Run the integrity check.  Exit codes:
#   0 → all OK, proceed
#   1 → manifest missing (fatal)
#   2 → tampered config files (fatal)
#   3 → unexpected error (fatal)
python3 /app/check_config_integrity.py \
    --manifest   "${MANIFEST}" \
    --config-dir "${CONFIG_DIR}"

EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
    echo ""
    echo "  ⛔  PRE-FLIGHT INTEGRITY CHECK FAILED (exit ${EXIT_CODE})"
    echo "  ⛔  Service '${SERVICE}' will NOT start."
    echo "  ⛔  Restore configuration files from a trusted baseline and redeploy."
    echo ""
    exit "$EXIT_CODE"
fi

echo ""
echo "  ✓  Pre-flight check passed — starting ${SERVICE}"
echo "═══════════════════════════════════════════════════════"
echo ""

# Replace this shell process with the actual service command.
# Using 'exec' ensures signals (SIGTERM, SIGINT) reach the service directly.
exec "$@"
