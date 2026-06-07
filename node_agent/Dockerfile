FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir psutil pyzmq pyyaml

CMD ["python", "agent.py"]
