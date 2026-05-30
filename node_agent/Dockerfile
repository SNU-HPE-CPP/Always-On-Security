FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install psutil pyzmq

CMD ["python", "agent.py"]
