FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    iproute2 \
    iptables \
    jq \
    python3 \
    python3-pip \
    sudo \
    suricata \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged system user.
# The security-monitor container is granted privileged + CAP_NET_ADMIN +
# CAP_NET_RAW in docker-compose.yml so that Suricata and the Zeek emulator
# can capture packets. Those capabilities are inherited by all processes in
# the container regardless of which Unix user launches them.
#
# Running the Python supervisor as a non-root user narrows the blast radius
# in the event of a code-execution vulnerability in the pipeline modules.
# Suricata is invoked via sudo so it gets the raw-socket access it needs
# while the rest of the pipeline runs as appuser.
#
# DOCKER_GID must match the host docker group GID (963 by default).
ARG DOCKER_GID=963
RUN groupadd -g ${DOCKER_GID} docker && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -G docker -m -s /bin/bash appuser && \
    echo "appuser ALL=(root) NOPASSWD: /usr/bin/suricata" >> /etc/sudoers

WORKDIR /opt/security-monitor

# Install Python pipeline dependencies
COPY security_monitor/requirements.txt /opt/security-monitor/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# psutil is used by the Zeek emulator shim to inspect local listeners
RUN pip3 install --no-cache-dir psutil==6.1.1

# Copy source — use the canonical shared secure_messenger, not the local copy
COPY security_monitor/ /opt/security-monitor/
COPY shared/secure_messenger.py /opt/security-monitor/secure_messenger.py

# Ensure runtime log directories are writable by appuser before dropping root
RUN mkdir -p /var/log/security /var/log/zeek /var/log/suricata /etc/suricata/rules \
    && chown -R appuser:appgroup /var/log/security /var/log/zeek /var/log/suricata \
    && chown -R appuser:appgroup /etc/suricata \
    && chown -R appuser:appgroup /opt/security-monitor

USER appuser

CMD ["python3", "main.py"]
