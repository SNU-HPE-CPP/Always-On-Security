FROM python:3.11-slim

WORKDIR /app

# Build context is the repo root (set in docker-compose.yml).
# requirements.txt and *.py live under risk_engine/
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

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "engine.py"]
