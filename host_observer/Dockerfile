FROM python:3.11-slim

# Create unprivileged system user.
# The docker group GID (999) is the default GID for the docker socket on most
# Linux hosts. The host-observer needs read-only docker.sock access to call
# Docker stats/top/get_archive APIs externally — it never runs inside tenant
# containers, and never execs commands inside them.
ARG DOCKER_GID=963
RUN groupadd -g ${DOCKER_GID} docker && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -G docker -m -s /bin/bash appuser

WORKDIR /app

COPY host_observer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the canonical shared secure_messenger — single source of truth.
COPY shared/secure_messenger.py ./secure_messenger.py
COPY host_observer/cluster_observer.py ./cluster_observer.py

RUN chown -R appuser:appgroup /app

USER appuser

CMD ["python", "cluster_observer.py"]
