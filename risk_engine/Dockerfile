FROM python:3.11-slim

# Install iptables for network quarantine enforcement and gosu for
# privilege drop in the entrypoint. CAP_NET_ADMIN is granted at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user.
# Add the docker group matching the host GID so appuser can access
# /var/run/docker.sock for network isolation (pause/quarantine).
ARG DOCKER_GID=963
RUN groupadd -g ${DOCKER_GID} docker && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -G docker -m -s /bin/bash appuser

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

# Label the service for audit records
ENV SERVICE_NAME=risk-engine

# Allow first-deployment without a manifest (set to false once baseline is committed)
ENV INTEGRITY_ALLOW_MISSING_MANIFEST=true

# ── Security: non-root user ────────────────────────────────────────────────
# Semgrep: dockerfile.security.missing-user-entrypoint (DL3002 / CKV_DOCKER_8)
#
# The risk-engine performs two privileged operations at runtime:
#   1. Docker API calls (container.stop / inspect) via /var/run/docker.sock
#      → handled by adding appuser to the 'docker' group (GID 999).
#   2. iptables DROP rules for node isolation (_pause action)
#      → handled by granting CAP_NET_ADMIN in docker-compose.yml.
#
# GID 999 is the standard Docker socket group on Debian/Ubuntu/RHEL hosts.
# If your host uses a different GID, override with:
#   docker compose run --group-add <host-docker-gid> risk-engine ...
RUN groupadd -r appgroup \
 && groupadd -f -g 999 docker \
 && useradd -r -g appgroup -G docker -u 1000 -d /app -s /sbin/nologin appuser \
 && mkdir -p /data/integrity_audits /data/forensics \
 && chown -R appuser:appgroup /data /app

USER appuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "engine.py"]