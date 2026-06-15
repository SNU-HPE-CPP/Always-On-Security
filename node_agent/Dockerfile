FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py security_collector.py secure_messenger.py fim_config.yaml ./

CMD ["python", "agent.py"]
