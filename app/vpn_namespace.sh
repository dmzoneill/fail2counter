#!/bin/bash
# Manage the msf_vpn network namespace with OpenVPN
# Usage: vpn_namespace.sh {start|stop|restart|status}

set -euo pipefail

NS="msf_vpn"
VETH_HOST="veth-msf-host"
VETH_NS="veth-msf-ns"
VPN_CONFIG="/opt/fail2counter/vpn.ovpn"
VPN_PID="/var/run/fail2counter-vpn.pid"
HOST_IP="10.200.1.1"
NS_IP="10.200.1.2"

start_namespace() {
    # Create namespace if it doesn't exist
    if ! ip netns list | grep -q "^${NS}"; then
        ip netns add "$NS"
        echo "[*] Created namespace $NS"
    fi

    # Bring up loopback in namespace
    ip netns exec "$NS" ip link set lo up

    # Create veth pair for DNS/connectivity to host
    if ! ip link show "$VETH_HOST" &>/dev/null; then
        ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
        ip link set "$VETH_NS" netns "$NS"

        # Configure host side
        ip addr add "${HOST_IP}/30" dev "$VETH_HOST" 2>/dev/null || true
        ip link set "$VETH_HOST" up

        # Configure namespace side
        ip netns exec "$NS" ip addr add "${NS_IP}/30" dev "$VETH_NS"
        ip netns exec "$NS" ip link set "$VETH_NS" up

        echo "[*] Created veth pair"
    fi

    # Enable NAT so namespace can reach the internet before VPN is up
    iptables -t nat -C POSTROUTING -s "${NS_IP}/30" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${NS_IP}/30" -j MASQUERADE

    # Allow forwarding through veth interface (FORWARD policy is DROP)
    iptables -C FORWARD -i "$VETH_HOST" -j ACCEPT 2>/dev/null || iptables -I FORWARD -i "$VETH_HOST" -j ACCEPT
    iptables -C FORWARD -o "$VETH_HOST" -j ACCEPT 2>/dev/null || iptables -I FORWARD -o "$VETH_HOST" -j ACCEPT

    # Set default route in namespace via host
    ip netns exec "$NS" ip route replace default via "$HOST_IP"

    # Copy resolv.conf into namespace
    mkdir -p /etc/netns/"$NS"
    cp /etc/resolv.conf /etc/netns/"$NS"/resolv.conf

    echo "[*] Namespace network configured"
}

start_vpn() {
    # Kill existing VPN if running
    stop_vpn

    if [ ! -f "$VPN_CONFIG" ]; then
        echo "[ERROR] VPN config not found: $VPN_CONFIG"
        return 1
    fi

    # Start OpenVPN inside the namespace
    ip netns exec "$NS" openvpn \
        --config "$VPN_CONFIG" \
        --daemon \
        --writepid "$VPN_PID" \
        --log /var/log/fail2counter-vpn.log \
        --verb 3

    # Wait for tunnel to come up
    for i in $(seq 1 30); do
        if ip netns exec "$NS" ip link show tun0 &>/dev/null; then
            VPN_IP=$(ip netns exec "$NS" ip -4 addr show tun0 | grep -oP 'inet \K[\d.]+')
            echo "[*] VPN tunnel up with IP: ${VPN_IP:-unknown}"
            return 0
        fi
        sleep 1
    done

    echo "[WARNING] VPN tunnel did not come up within 30s"
    return 1
}

stop_vpn() {
    if [ -f "$VPN_PID" ]; then
        kill "$(cat "$VPN_PID")" 2>/dev/null || true
        rm -f "$VPN_PID"
        sleep 2
        echo "[*] VPN stopped"
    fi
}

stop_namespace() {
    stop_vpn
    ip link del "$VETH_HOST" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "${NS_IP}/30" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$VETH_HOST" -j ACCEPT 2>/dev/null || true
    rm -rf /etc/netns/"$NS"
    echo "[*] Namespace $NS removed"
}

status() {
    if ip netns list | grep -q "^${NS}"; then
        echo "Namespace: UP"
        if [ -f "$VPN_PID" ] && kill -0 "$(cat "$VPN_PID")" 2>/dev/null; then
            VPN_IP=$(ip netns exec "$NS" ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "unknown")
            echo "VPN: UP (PID $(cat "$VPN_PID"), IP: $VPN_IP)"
        else
            echo "VPN: DOWN"
        fi
    else
        echo "Namespace: DOWN"
        echo "VPN: DOWN"
    fi
}

case "${1:-}" in
    start)
        start_namespace
        start_vpn
        ;;
    stop)
        stop_namespace
        ;;
    restart-vpn)
        start_vpn
        ;;
    restart)
        stop_namespace
        start_namespace
        start_vpn
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|restart-vpn|status}"
        exit 1
        ;;
esac
