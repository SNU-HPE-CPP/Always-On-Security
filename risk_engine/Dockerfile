FROM python:3.11-slim

# Install iptables for network quarantine enforcement and gosu for
# privilege drop in the entrypoint. CAP_NET_ADMIN is granted at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user.
# Add the docker group matching the host GID so appuser can access
# the Docker socket proxy for network isolation (pause/quarantine).
# FIX #3: Removed duplicate groupadd/useradd/docker block that appeared below.
ARG DOCKER_GID=963
RUN groupadd -g ${DOCKER_GID} docker && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -G docker -m -s /bin/bash appuser && \
    mkdir -p /data/integrity_audits /data/forensics && \
    chown -R appuser:appgroup /data

WORKDIR /app

# Build context is the repo root (set in docker-compose.yml).
# risk_engine/requirements.txt and *.py live under risk_engine/
COPY risk_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY risk_engine/*.py ./

# ── REC-08: Pre-flight config integrity check ─────────────────────────────
# scripts/ is directly accessible from the repo-root build context.
COPY scripts/check_config_integrity.py ./check_config_integrity.py
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown -R appuser:appgroup /app

# Label the service for audit records
ENV SERVICE_NAME=risk-engine

# Allow first-deployment without a manifest (set to false once baseline is committed)
ENV INTEGRITY_ALLOW_MISSING_MANIFEST=true

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "engine.py"]