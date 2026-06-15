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

COPY risk_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY risk_engine/*.py ./
COPY risk_engine/config/ ./config/

RUN chown -R appuser:appgroup /app

# Entrypoint: fix /data ownership (named volume is created as root) then drop privileges
COPY risk_engine/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Keep root for entrypoint; it drops to appuser after chown
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "engine.py"]
