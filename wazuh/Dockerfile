FROM python:3.11-slim

# Create unprivileged system user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

COPY . .

RUN chown -R appuser:appgroup /app

USER appuser

CMD ["python", "wazuh.py"]
