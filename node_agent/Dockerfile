FROM python:3.11-slim

# Create unprivileged system user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

WORKDIR /home/appuser/app

COPY agent.py ./

RUN chown -R appuser:appgroup /home/appuser/app

USER appuser

CMD ["python", "agent.py"]
