FROM python:3.11-slim

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

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "controller.py"]
