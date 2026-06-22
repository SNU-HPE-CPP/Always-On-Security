FROM python:3.11-slim

# gosu: minimal setuid helper used by entrypoint to drop privileges after chown
RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser && \
    mkdir -p /data/integrity_audits

WORKDIR /app

# Python dependencies
COPY controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application
COPY controller/ ./
COPY shared/secure_messenger.py ./secure_messenger.py

# Integrity tooling
COPY scripts/check_config_integrity.py ./check_config_integrity.py
COPY scripts/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

RUN chown -R appuser:appgroup /app

ENV SERVICE_NAME=controller
ENV INTEGRITY_ALLOW_MISSING_MANIFEST=true

# IMPORTANT:
# Do NOT switch to appuser here.
# entrypoint runs as root, fixes permissions,
# then drops privileges via gosu.
ENTRYPOINT ["/entrypoint.sh"]

CMD ["python", "controller.py"]