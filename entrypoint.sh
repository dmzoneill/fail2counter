#!/bin/bash
set -e

CONFIG_DIR="/etc/fail2counter"
ENV_FILE="${CONFIG_DIR}/.env"

# --- Load .env file ---
if [ -f "$ENV_FILE" ] && [ -r "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "[WARNING] .env file not found or not readable at $ENV_FILE"
fi

# --- Validate required config ---
if [ -z "$NOTIFICATION_EMAIL" ]; then
    echo "[FATAL] NOTIFICATION_EMAIL not set. Create .env file from .env.example"
    exit 1
fi

if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$ANTHROPIC_VERTEX_PROJECT_ID" ]; then
    echo "[FATAL] No AI provider configured. Set ANTHROPIC_API_KEY or ANTHROPIC_VERTEX_PROJECT_ID in .env"
    exit 1
fi

# --- Defaults ---
export FAIL2COUNTER_DSN="${FAIL2COUNTER_DSN:-host=/var/run/postgresql dbname=fail2counter user=postgres}"
export NOTIFICATION_FROM="${NOTIFICATION_FROM:-fail2counter@localhost}"
export SMTP_HOST="${SMTP_HOST:-localhost}"
export SMTP_PORT="${SMTP_PORT:-25}"
export VPN_ROTATE_INTERVAL="${VPN_ROTATE_INTERVAL:-30}"

# --- Start PostgreSQL ---
echo "[*] Starting PostgreSQL..."

# Set trust auth for local connections (container-only, no external exposure)
PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)
if [ -n "$PG_HBA" ]; then
    sed -i 's/^local\s\+all\s\+all\s\+peer/local   all             all                                     trust/' "$PG_HBA"
    sed -i 's/^local\s\+all\s\+postgres\s\+peer/local   all             postgres                                trust/' "$PG_HBA"
fi

pg_ctlcluster 15 main start 2>/dev/null || true
sleep 2

# Setup database
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'fail2counter'\" | grep -q 1 || createdb fail2counter" 2>/dev/null
su - postgres -c "psql -d fail2counter -f /opt/fail2counter/schema.sql" 2>/dev/null
echo "[*] PostgreSQL ready"

# --- Start Redis ---
echo "[*] Starting Redis..."
redis-server --daemonize yes --loglevel warning
sleep 1
echo "[*] Redis ready"

# --- Initialize Metasploit database ---
if [ ! -f /opt/fail2counter/.msf_initialized ]; then
    echo "[*] Initializing Metasploit database (first run)..."
    su - postgres -c "msfdb init" 2>/dev/null || true
    touch /opt/fail2counter/.msf_initialized
fi

# --- Setup VPN namespace if .ovpn provided ---
if [ -f "${CONFIG_DIR}/vpn.ovpn" ]; then
    echo "[*] Setting up VPN namespace..."
    /opt/fail2counter/vpn_namespace.sh start 2>&1 || echo "[WARNING] VPN setup failed, continuing without VPN"
else
    echo "[*] No VPN config found, scanning without VPN"
fi

echo "[*] Starting fail2counter worker..."
exec /opt/fail2counter/fail2counter_worker.py
