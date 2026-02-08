#!/bin/bash
set -e

CONFIG_DIR="/etc/fail2counter"
CONFIG_FILE="${CONFIG_DIR}/fail2counter.conf"

# --- Load configuration ---
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[FATAL] Configuration file not found: $CONFIG_FILE"
    echo "Run: fail2counter-setup to generate it"
    exit 1
fi

source "$CONFIG_FILE"

# --- Validate required config ---
if [ -z "$NOTIFICATION_EMAIL" ]; then
    echo "[FATAL] NOTIFICATION_EMAIL not set in $CONFIG_FILE"
    exit 1
fi

if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$ANTHROPIC_VERTEX_PROJECT_ID" ]; then
    echo "[FATAL] No AI provider configured. Set ANTHROPIC_API_KEY or ANTHROPIC_VERTEX_PROJECT_ID"
    exit 1
fi

# --- Start PostgreSQL ---
echo "[*] Starting PostgreSQL..."
pg_ctlcluster 15 main start 2>/dev/null || true
sleep 2

# Create database and user
su - postgres -c "psql -c \"SELECT 1 FROM pg_database WHERE datname = 'fail2counter'\" -t | grep -q 1 || createdb fail2counter" 2>/dev/null
su - postgres -c "psql -c \"DO \\\$\\\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fail2counter') THEN CREATE ROLE fail2counter WITH LOGIN; END IF; END \\\$\\\$;\"" 2>/dev/null
su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE fail2counter TO fail2counter;\"" 2>/dev/null
su - postgres -c "psql -d fail2counter -f /opt/fail2counter/schema.sql" 2>/dev/null
su - postgres -c "psql -d fail2counter -c \"GRANT ALL ON ALL TABLES IN SCHEMA public TO fail2counter; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO fail2counter;\"" 2>/dev/null
echo "[*] PostgreSQL ready"

# --- Start Redis ---
echo "[*] Starting Redis..."
redis-server --daemonize yes --loglevel warning
sleep 1
echo "[*] Redis ready"

# --- Initialize Metasploit database ---
if [ ! -f /opt/fail2counter/.msf_initialized ]; then
    echo "[*] Initializing Metasploit database (first run)..."
    msfdb init 2>/dev/null || true
    touch /opt/fail2counter/.msf_initialized
fi

# --- Setup VPN namespace if .ovpn provided ---
if [ -f "${CONFIG_DIR}/vpn.ovpn" ]; then
    echo "[*] Setting up VPN namespace..."
    /opt/fail2counter/vpn_namespace.sh start || echo "[WARNING] VPN setup failed, continuing without VPN"
else
    echo "[*] No VPN config found, scanning without VPN"
fi

# --- Export environment for worker ---
export REDIS_PASSWORD=""
export FAIL2COUNTER_DSN="host=/var/run/postgresql dbname=fail2counter user=postgres"
export NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL}"

# AI provider config
if [ -n "$ANTHROPIC_VERTEX_PROJECT_ID" ]; then
    export ANTHROPIC_VERTEX_PROJECT_ID
    export ANTHROPIC_VERTEX_REGION="${ANTHROPIC_VERTEX_REGION:-us-east5}"
    [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ] && export GOOGLE_APPLICATION_CREDENTIALS
fi
if [ -n "$ANTHROPIC_API_KEY" ]; then
    export ANTHROPIC_API_KEY
fi

echo "[*] Starting fail2counter worker..."
exec /opt/fail2counter/fail2counter_worker.py
