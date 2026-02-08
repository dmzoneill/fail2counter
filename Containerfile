FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql postgresql-contrib \
    redis-server \
    nmap \
    openvpn \
    iproute2 \
    iptables \
    python3 python3-pip python3-venv \
    curl wget ca-certificates gnupg \
    supervisor \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Metasploit Framework
RUN curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall \
    && chmod 755 /tmp/msfinstall \
    && /tmp/msfinstall \
    && rm /tmp/msfinstall

# Python dependencies
RUN pip3 install --break-system-packages \
    anthropic[vertex] \
    psycopg2-binary \
    redis

# Create directories
RUN mkdir -p /opt/fail2counter /var/log/fail2counter /etc/fail2counter

# Copy application files
COPY app/fail2counter_worker.py /opt/fail2counter/
COPY app/ai.py /opt/fail2counter/
COPY app/fail2counter_push_ip.py /opt/fail2counter/
COPY app/schema.sql /opt/fail2counter/
COPY app/refresh_exploits.sh /opt/fail2counter/
COPY app/vpn_namespace.sh /opt/fail2counter/
COPY app/exploits.txt /opt/fail2counter/
RUN chmod +x /opt/fail2counter/*.py /opt/fail2counter/*.sh

# Copy supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/fail2counter.conf

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose nothing by default — this container makes outbound connections only
VOLUME ["/etc/fail2counter"]

ENTRYPOINT ["/entrypoint.sh"]
