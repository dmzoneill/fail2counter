#!/usr/bin/env python3
"""Push a banned IP to the fail2counter Redis queue."""

import sys
from datetime import datetime, timezone

import redis

if len(sys.argv) < 2:
    print("Usage: fail2counter_push_ip.py <ip>")
    sys.exit(1)

ip = sys.argv[1]

try:
    r = redis.Redis(host="localhost", port=6379, db=0)
    timestamp = datetime.now(timezone.utc).isoformat()
    r.rpush("banned_ips", f"{timestamp}|{ip}")
except Exception as e:
    print(f"Failed to queue IP {ip}: {e}")
    sys.exit(1)
