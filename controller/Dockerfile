FROM python:3.11-slim

# gosu: minimal setuid helper used by entrypoint to drop privileges after chown
RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

COPY controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the canonical shared secure_messenger — no per-component copies needed.
COPY shared/secure_messenger.py ./secure_messenger.py
COPY controller/controller.py ./controller.py

RUN chown -R appuser:appgroup /app

# Entrypoint: fix /data ownership (named volume is created as root) then drop privileges
COPY controller/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Keep root for entrypoint; it drops to appuser after chown
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "controller.py"]
