FROM python:3.11-slim

# gosu: minimal setuid helper used by entrypoint to drop privileges after chown
RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user.
# /data is pre-created and owned by appuser so integrity audit records can
# be written without elevated permissions.
# FIX #1: Removed duplicate groupadd/useradd block that was present below.
# FIX #2: Added COPY shared/secure_messenger.py (required by controller.py import).
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser && \
    mkdir -p /data/integrity_audits && \
    chown -R appuser:appgroup /data

WORKDIR /app

# Build context is the repo root (set in docker-compose.yml).
# Source files live under controller/
COPY controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY controller/ ./
COPY shared/secure_messenger.py ./secure_messenger.py

# ── REC-08: Pre-flight config integrity check ─────────────────────────────
# scripts/ is directly accessible from the repo-root build context.
COPY scripts/check_config_integrity.py ./check_config_integrity.py
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown -R appuser:appgroup /app

ENV SERVICE_NAME=controller
ENV INTEGRITY_ALLOW_MISSING_MANIFEST=true

USER appuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "controller.py"]
