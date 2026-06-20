FROM python:3.11-slim

# gosu: minimal setuid helper used by entrypoint to drop privileges after chown
RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

# Build context is the repo root (set in docker-compose.yml).
# Source files live under controller/
COPY controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY controller/ ./

# ── REC-08: Pre-flight config integrity check ─────────────────────────────
# scripts/ is directly accessible from the repo-root build context.
COPY scripts/check_config_integrity.py ./check_config_integrity.py
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SERVICE_NAME=controller
ENV INTEGRITY_ALLOW_MISSING_MANIFEST=true

# ── Security: non-root user ────────────────────────────────────────────────
# Semgrep: dockerfile.security.missing-user-entrypoint (DL3002 / CKV_DOCKER_8)
# The controller does not run iptables — a plain non-root user is sufficient.
# /data is pre-created and owned by appuser so integrity audit records can
# be written without elevated permissions.
RUN groupadd -r appgroup \
 && useradd -r -g appgroup -u 1000 -d /app -s /sbin/nologin appuser \
 && mkdir -p /data/integrity_audits \
 && chown -R appuser:appgroup /data /app

USER appuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "controller.py"]
