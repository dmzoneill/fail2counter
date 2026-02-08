#!/bin/bash
# Test fail2counter without fail2ban or host modifications
# Builds the image, runs the container, and queues a test IP

set -euo pipefail

IMAGE_NAME="fail2counter"
CONTAINER_NAME="fail2counter-test"
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="/tmp/fail2counter-test"

# --- Check for .env ---
if [ ! -f "$TEST_DIR/.env" ]; then
    echo "No .env file found. Creating from .env.example..."
    echo ""
    echo "Edit .env with your API key, then re-run this script."
    cp "$TEST_DIR/.env.example" "$TEST_DIR/.env"
    exit 1
fi

# --- Setup temp config dir ---
rm -rf "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
cp "$TEST_DIR/.env" "$CONFIG_DIR/.env"
chmod 644 "$CONFIG_DIR/.env"

# Copy VPN config if it exists
if [ -f "$TEST_DIR/vpn.ovpn" ]; then
    cp "$TEST_DIR/vpn.ovpn" "$CONFIG_DIR/vpn.ovpn"
    chmod 644 "$CONFIG_DIR/vpn.ovpn"
fi

# Copy GCP credentials if referenced
GCP_CREDS=$(grep "^GOOGLE_APPLICATION_CREDENTIALS=" "$CONFIG_DIR/.env" 2>/dev/null | cut -d= -f2 || true)
if [ -n "$GCP_CREDS" ] && [ -f "$GCP_CREDS" ]; then
    cp "$GCP_CREDS" "$CONFIG_DIR/gcp-credentials.json"
    chmod 644 "$CONFIG_DIR/gcp-credentials.json"
fi

# --- Build image ---
echo "[*] Building container image..."
podman build -t "$IMAGE_NAME" -f "$TEST_DIR/Containerfile" "$TEST_DIR"

# --- Stop old test container ---
podman stop "$CONTAINER_NAME" 2>/dev/null || true
podman rm "$CONTAINER_NAME" 2>/dev/null || true

# --- Run container ---
echo "[*] Starting test container..."
podman run -d \
    --name "$CONTAINER_NAME" \
    --cap-add NET_ADMIN \
    --cap-add SYS_ADMIN \
    --device /dev/net/tun \
    -v "$CONFIG_DIR:/etc/fail2counter:ro,z" \
    "$IMAGE_NAME"

echo "[*] Waiting for services to start..."
sleep 10

# --- Show startup logs ---
echo ""
echo "=== Startup Logs ==="
podman logs "$CONTAINER_NAME" 2>&1 | tail -20
echo ""

# --- Queue a test IP ---
TEST_IP="${1:-93.174.95.106}"
echo "[*] Queuing test IP: $TEST_IP"
podman exec "$CONTAINER_NAME" /opt/fail2counter/fail2counter_push_ip.py "$TEST_IP"

echo ""
echo "=== Container running ==="
echo ""
echo "Follow logs:     podman logs -f $CONTAINER_NAME"
echo "Queue another:   podman exec $CONTAINER_NAME /opt/fail2counter/fail2counter_push_ip.py <IP>"
echo "Check DB:        podman exec $CONTAINER_NAME psql -U postgres -d fail2counter -c 'SELECT * FROM hosts;'"
echo "Stop:            podman stop $CONTAINER_NAME && podman rm $CONTAINER_NAME"
echo ""
