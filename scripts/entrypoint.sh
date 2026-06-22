#!/bin/sh
# =============================================================================
# Always-On Security — Service Entrypoint with Pre-flight Integrity Check
# =============================================================================

set -e

MANIFEST="${CONFIG_HASHES_PATH:-/opt/security/config/config_hashes.yaml}"
CONFIG_DIR="${CONFIG_DIR:-/opt/security/config}"
SERVICE="${SERVICE_NAME:-$(basename "$0")}"

# -----------------------------------------------------------------------------
# Fix permissions on mounted Docker volumes BEFORE any checks run.
# Docker volumes are typically mounted as root:root and override image-time
# ownership settings.
# -----------------------------------------------------------------------------

mkdir -p /data
mkdir -p /data/integrity_audits
mkdir -p /data/forensics

chown -R appuser:appgroup /data

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Always-On Security — Pre-flight Check"
echo "  Service : ${SERVICE}"
echo "  Time    : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "═══════════════════════════════════════════════════════"

# -----------------------------------------------------------------------------
# Integrity verification
# -----------------------------------------------------------------------------

ALLOW_MISSING_FLAG=""

if [ "${INTEGRITY_ALLOW_MISSING_MANIFEST:-false}" = "true" ]; then
    ALLOW_MISSING_FLAG="--allow-missing-manifest"
fi

python3 /app/check_config_integrity.py \
    --manifest "${MANIFEST}" \
    --config-dir "${CONFIG_DIR}" \
    ${ALLOW_MISSING_FLAG}

EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
    echo ""
    echo "  ⛔ PRE-FLIGHT INTEGRITY CHECK FAILED (exit ${EXIT_CODE})"
    echo "  ⛔ Service '${SERVICE}' will NOT start."
    echo "  ⛔ Restore configuration files from a trusted baseline and redeploy."
    echo ""
    exit "$EXIT_CODE"
fi

echo ""
echo "  ✓ Pre-flight check passed — starting ${SERVICE}"
echo "═══════════════════════════════════════════════════════"
echo ""

# -----------------------------------------------------------------------------
# Drop privileges and run service
# -----------------------------------------------------------------------------

exec gosu appuser "$@"