FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir pyzmq

COPY . .

CMD ["python", "-u", "provider.py"]