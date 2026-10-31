#!/usr/bin/env python3
"""fail2counter worker: scan banned IPs from Redis, record results in PostgreSQL."""

import importlib
import ipaddress
import os
import re
import smtplib
import socket
import subprocess  # nosec B404
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

import psycopg2
import psycopg2.extras
import redis

# Allow importing ai.py from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ai = importlib.import_module("ai")

# CONFIG
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_QUEUE = "banned_ips"
SCAN_TIMEOUT = 600
PRECHECK_TIMEOUT = 30
MIN_EXPECTED_OUTPUT_BYTES = 500
# Private (0700) per-process directory for nmap output files
WORK_DIR = tempfile.mkdtemp(prefix="fail2counter_")
TMP_OUTPUT = os.path.join(WORK_DIR, "nmap_result.txt")
FASTSCAN_FILE = os.path.join(WORK_DIR, "nmap_fastscan.txt")
PRECHECK_FILE = os.path.join(WORK_DIR, "nmap_precheck.txt")
SCHEMA_FILE = "/opt/fail2counter/schema.sql"
VPN_ROTATE_INTERVAL = int(os.environ.get("VPN_ROTATE_INTERVAL", "30"))
VPN_SCRIPT = "/opt/fail2counter/vpn_namespace.sh"
NETNS = "msf_vpn"
NETNS_CMD = ["ip", "netns", "exec", NETNS]
PG_DSN = os.environ.get(
    "FAIL2COUNTER_DSN",
    "host=/var/run/postgresql dbname=fail2counter user=postgres",
)
PORT_LIST_RE = re.compile(r"^\d{1,5}(,\d{1,5})*$")
# Errors we expect from external I/O (nmap/subprocess, sockets, parsing, AI, DB).
SCAN_ERRORS = (
    OSError,
    ValueError,
    KeyError,
    TypeError,
    RuntimeError,
    subprocess.SubprocessError,
    redis.RedisError,
    psycopg2.Error,
)

logs: list[str] = []


def utc_now() -> datetime:
    """Return the current UTC time as a naive datetime (same shape as utcnow())."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def log(text, level="INFO"):
    """Print a timestamped log line."""
    print(f"[{utc_now().isoformat()}] [{level}] {text}")


def capture(text, level="INFO"):
    """Log a line and keep it for the per-scan report."""
    log(text, level)
    logs.append(f"[{utc_now().isoformat()}] [{level}] {text}")


class Database:
    """PostgreSQL connection holder that reconnects when the link drops."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.conn: Any = None
        self.cursor: Any = None
        self.connect()

    def connect(self):
        """Open a new autocommit connection and dict cursor."""
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = True
        self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def ensure(self):
        """Reconnect if the current connection is no longer usable."""
        try:
            _ = self.conn.isolation_level
        except psycopg2.Error:
            self.connect()


# --- Insert functions ---


def insert_host(db: Database, ip: str, hostname: str | None) -> int:
    """Insert or update a host row and return its id."""
    db.cursor.execute("SELECT id FROM hosts WHERE ip_address = %s", (ip,))
    row = db.cursor.fetchone()
    if row:
        return row["id"]
    db.cursor.execute(
        "INSERT INTO hosts (ip_address, hostname) VALUES (%s, %s) RETURNING id",
        (ip, hostname),
    )
    return db.cursor.fetchone()["id"]


def insert_scan(db: Database, host_id: int, scan: dict) -> int:
    """Insert a scan row from a scan detail dict and return its id."""
    db.cursor.execute(
        "INSERT INTO scans (host_id, scan_time, scan_type, latency_seconds, duration_seconds) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING id",
        (host_id, scan["scan_time"], scan["scan_type"], scan["latency"], scan["duration"]),
    )
    return db.cursor.fetchone()["id"]


def insert_port(db: Database, scan_id: int, port: int, protocol: str, state: str) -> int:
    """Insert a port row and return its id."""
    db.cursor.execute(
        "INSERT INTO ports (scan_id, port_number, protocol, state) VALUES (%s, %s, %s, %s) RETURNING id",
        (scan_id, port, protocol, state),
    )
    return db.cursor.fetchone()["id"]


def insert_service(db: Database, port_id: int, service: dict):
    """Insert a service row for ``port_id`` from a service detail dict."""
    db.cursor.execute(
        "INSERT INTO services (port_id, service_name, product, version, is_ssl, recognized) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            port_id,
            service["service_name"],
            service.get("product"),
            service.get("version"),
            service.get("is_ssl", False),
            service.get("recognized", True),
        ),
    )


# --- Exploit analysis insert functions ---


def insert_exploit(db: Database, scan_id: int, host_id: int, result: dict) -> int:
    """Insert an exploit row from an AI result dict and return its id."""
    db.cursor.execute(
        """INSERT INTO exploits
           (scan_id, host_id, module_path, rhosts, rport, rc_file_path, status)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (
            scan_id,
            host_id,
            result["module_path"],
            result["rhosts"],
            result["rport"],
            result["rc_path"],
            result["status"],
        ),
    )
    return db.cursor.fetchone()["id"]


def insert_exploit_result(db: Database, exploit_id: int, result: dict) -> int:
    """Insert an exploit result row from an AI result dict and return its id."""
    db.cursor.execute(
        """INSERT INTO exploit_results
           (exploit_id, output_text, exit_code, duration_seconds)
           VALUES (%s, %s, %s, %s) RETURNING id""",
        (exploit_id, result["output"], result["exit_code"], result["duration"]),
    )
    return db.cursor.fetchone()["id"]


def insert_notification(db: Database, host_id: int, exploit_id: int, message: str) -> int:
    """Insert an abuse-contact notification row and return its id."""
    db.cursor.execute(
        """INSERT INTO notifications
           (host_id, exploit_id, notification_type, status, contact_info, message)
           VALUES (%s, %s, 'abuse_contact', 'pending', %s, %s) RETURNING id""",
        (host_id, exploit_id, None, message),
    )
    return db.cursor.fetchone()["id"]


# --- Utility functions ---


def validate_ip(value: str) -> str:
    """Return ``value`` normalised as an IP address, or raise ValueError."""
    return str(ipaddress.ip_address(value.strip()))


def validate_ports(value: str) -> str:
    """Return a comma separated port list, or raise ValueError."""
    if not PORT_LIST_RE.match(value) or any(not 0 < int(p) < 65536 for p in value.split(",")):
        raise ValueError(f"Invalid port list: {value!r}")
    return value


def run_nmap(nmap_args: list[str], timeout: int, **kwargs):
    """Run nmap inside the VPN network namespace with a hard timeout.

    Every caller passes arguments that were validated with ``validate_ip``
    or ``validate_ports``; the command is an argument list, never a shell.
    """
    cmd = [*NETNS_CMD, "timeout", str(timeout), "nmap", *nmap_args]
    return subprocess.run(cmd, check=True, **kwargs)  # nosec B603 # nosemgrep


def rotate_vpn():
    """Restart VPN in the network namespace to get a new exit IP."""
    try:
        result = subprocess.run(  # nosec B603
            [VPN_SCRIPT, "restart-vpn"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        capture(f"VPN rotated: {result.stdout.strip()}")
    except (OSError, subprocess.SubprocessError) as exc:
        capture(f"VPN rotation failed: {exc}", level="WARNING")


def send_email(subject: str, body: str, to_email: str | None = None):
    """Send a notification email via the local SMTP server."""
    if to_email is None:
        to_email = os.environ.get("NOTIFICATION_EMAIL", "root@localhost")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("NOTIFICATION_FROM", "fail2counter@localhost")
    msg["To"] = to_email
    msg.set_content(body)

    try:
        smtp_host = os.environ.get("SMTP_HOST", "localhost")
        smtp_port = int(os.environ.get("SMTP_PORT", "25"))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.send_message(msg)
        capture(f"Email sent to {to_email}")
    except (OSError, smtplib.SMTPException) as exc:
        capture(f"Failed to send email: {exc}", level="ERROR")


def init_schema(db: Database):
    """Initialize database schema from schema.sql."""
    if not os.path.exists(SCHEMA_FILE):
        log("schema.sql not found, skipping schema init", "WARNING")
        return
    with open(SCHEMA_FILE, encoding="utf-8") as schema:
        sql = schema.read()
    db.cursor.execute(sql)
    log("Database schema initialized")


def precheck_host(ip: str) -> bool:
    """Return True if the host is up, False if it is down or the precheck failed."""
    capture(f"Running precheck for {ip}")
    try:
        with open(PRECHECK_FILE, "w", encoding="utf-8") as precheck_out:
            run_nmap(["-sn", ip], PRECHECK_TIMEOUT, stdout=precheck_out, stderr=subprocess.DEVNULL)
        with open(PRECHECK_FILE, encoding="utf-8") as handle:
            lines = handle.read()
        capture(lines, "INFO")
        if "Host seems down" in lines:
            capture(f"[SKIP] Host {ip} seems down")
            return False
        return True
    except subprocess.CalledProcessError:
        capture(f"[SKIP] Precheck failed or timed out for {ip}", level="WARNING")
        return False


def fast_scan(ip: str) -> str:
    """Return a validated comma-separated open-port list for ``ip`` (may be empty)."""
    capture(f"Running fast port scan on {ip}")
    run_nmap(
        ["-T4", "-F", "-oG", FASTSCAN_FILE, "-v", ip],
        SCAN_TIMEOUT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(FASTSCAN_FILE, encoding="utf-8") as handle:
        grepable = handle.read()
    capture(grepable, "INFO")
    matches = re.findall(r"(\d+)/open", grepable)
    capture(matches, "DEBUG")
    return validate_ports(",".join(matches)) if matches else ""


def version_scan(ip: str, ports: str) -> str | None:
    """Run a service version scan and return its output, or None if it is too small."""
    capture(f"Running service version detection for {ip}")
    try:
        with open(TMP_OUTPUT, "w", encoding="utf-8") as out:
            run_nmap(
                [
                    "-sV",
                    "--version-light",
                    "--max-retries",
                    "1",
                    "--min-parallelism",
                    "10",
                    "--host-timeout",
                    "60s",
                    "-p",
                    ports,
                    "-T4",
                    "-v",
                    ip,
                ],
                SCAN_TIMEOUT,
                stdout=out,
                stderr=out,
            )
        capture(f"Scan completed for {ip}")
    except subprocess.CalledProcessError:
        capture(f"Nmap scan failed or timed out for {ip}", level="WARNING")

    with open(TMP_OUTPUT, encoding="utf-8") as handle:
        nmap_output = handle.read()
    capture(nmap_output, "DEBUG")
    if len(nmap_output) < MIN_EXPECTED_OUTPUT_BYTES:
        capture(f"Skipping {ip} due to small output", level="WARNING")
        return None
    capture(f"Nmap output size: {len(nmap_output)} bytes")
    return nmap_output


def parse_services(db: Database, scan_id: int, nmap_output: str) -> list[dict]:
    """Insert every open-port service from ``nmap_output`` and return their details."""
    service_matches = re.finditer(
        r"(?P<port>\d+)/tcp\s+open\s+(?P<service>[^\s]+)(?:\s+(?P<product>[^\s]+)(?:\s+(?P<version>[^\s]+))?)?",
        nmap_output,
    )
    detected_services = []
    for match in service_matches:
        port = int(match.group("port"))
        raw_name = match.group("service")
        service = {
            "service_name": raw_name.rstrip("?"),
            "product": match.group("product") or None,
            "version": match.group("version") or None,
            "is_ssl": "ssl" in raw_name.lower() or port in (443, 465, 993, 995),
            "recognized": not raw_name.endswith("?"),
        }
        capture(f"[DB] Inserting port {port} for scan_id: {scan_id}", "DEBUG")
        port_id = insert_port(db, scan_id, port, "tcp", "open")
        insert_service(db, port_id, service)
        detected_services.append({"port": port, **service})
    return detected_services


def run_exploit_analysis(db: Database, scan: dict, detected_services: list[dict], exploit_index) -> list[str]:
    """Run the AI exploit phase for ``scan`` and return human-readable summary lines.

    ``scan`` carries ip, nmap_output, scan_id, host_id and hostname.
    """
    summary_lines: list[str] = []
    if not detected_services:
        return summary_lines
    ip = scan["ip"]
    try:
        capture(f"Starting AI exploit analysis for {ip}...")
        ai_results = ai.analyze(
            ip=ip,
            nmap_output=scan["nmap_output"],
            services=detected_services,
            exploit_index=exploit_index,
            log_fn=capture,
        )
        for result in ai_results:
            exploit_id = insert_exploit(db, scan["scan_id"], scan["host_id"], result)
            insert_exploit_result(db, exploit_id, result)
            summary_lines.append(
                f"  [{result['status'].upper()}] {result['module_path']} "
                f"-> {result['rhosts']}:{result['rport']} ({result['duration']:.1f}s)"
            )
            if result["status"] == "success":
                message = (
                    f"Vulnerability confirmed on {ip} ({scan['hostname'] or 'unknown'}):\n"
                    f"Module: {result['module_path']}\n"
                    f"Port: {result['rport']}\n"
                    f"This host attacked our infrastructure and appears to be compromised."
                )
                insert_notification(db, scan["host_id"], exploit_id, message)
        capture(f"AI exploit analysis complete: {len(ai_results)} modules tested")
    except SCAN_ERRORS as exc:
        capture(f"AI exploit analysis failed: {exc}", level="ERROR")
    return summary_lines


def process_ip(db: Database, ip: str, exploit_index) -> None:
    """Run the full scan-and-store pipeline for a single IP."""
    if not precheck_host(ip):
        return

    try:
        ports = fast_scan(ip)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        capture(f"Fast scan failed: {exc}", level="ERROR")
        return
    if not ports:
        capture(f"No open ports found on {ip}", level="WARNING")
        return
    capture(f"Open ports: {ports}")

    try:
        nmap_output = version_scan(ip, ports)
    except OSError as exc:
        capture(f"Failed to read Nmap output: {exc}", level="ERROR")
        return
    if nmap_output is None:
        return

    try:
        hostname: str | None = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = None

    capture(f"[DB] About to insert host: {ip} (hostname: {hostname})", "DEBUG")
    host_id = insert_host(db, ip, hostname)
    capture(f"[DB] Inserted host with ID: {host_id}", "DEBUG")

    latency_match = re.search(r"Host is up \(([\d.]+)s latency\)", nmap_output)
    duration_match = re.search(r"scanned in ([\d.]+) seconds", nmap_output)
    scan = {
        "ip": ip,
        "nmap_output": nmap_output,
        "host_id": host_id,
        "hostname": hostname,
        "scan_time": utc_now(),
        "scan_type": "version",
        "latency": float(latency_match.group(1)) if latency_match else 0.0,
        "duration": float(duration_match.group(1)) if duration_match else 0.0,
    }
    scan_id = insert_scan(db, host_id, scan)
    scan["scan_id"] = scan_id
    capture(f"[DB] Inserted scan with ID: {scan_id}", "DEBUG")

    detected_services = parse_services(db, scan_id, nmap_output)
    summary_lines = run_exploit_analysis(db, scan, detected_services, exploit_index)

    email_body = "\n".join(logs)
    if summary_lines:
        email_body += "\n\n=== EXPLOIT ANALYSIS RESULTS ===\n" + "\n".join(summary_lines)
    try:
        db.conn.commit()
    except psycopg2.Error as exc:
        capture(f"[DB] Manual commit failed: {exc}", "ERROR")
        capture(f"[DB] Traceback:\n{traceback.format_exc()}", "ERROR")

    send_email(subject=f"[Fail2Counter] Analysis for {ip}", body=email_body)


def main() -> int:
    """Connect to services and process banned IPs from the Redis queue forever."""
    db = Database(PG_DSN)
    init_schema(db)

    capture("Loading exploit index...")
    exploit_index = ai.ExploitIndex()
    capture(f"Exploit index ready: {len(exploit_index.modules)} modules")

    try:
        queue = redis.Redis(
            host=os.environ.get("REDIS_HOST", "localhost"),
            port=int(os.environ.get("REDIS_PORT", "6379")),
            db=0,
            password=REDIS_PASSWORD or None,
        )
        queue.ping()
        capture("Connected to Redis successfully.")
    except redis.RedisError as exc:
        capture(f"Failed to connect to Redis: {exc}", level="ERROR")
        return 3

    scan_count = 0
    while True:
        logs.clear()
        db.ensure()

        try:
            ip_entry = queue.lpop(REDIS_QUEUE)
        except redis.RedisError as exc:
            capture(f"Redis error while reading queue: {exc}", level="ERROR")
            time.sleep(10)
            continue

        if not ip_entry:
            time.sleep(10)
            continue

        try:
            timestamp, raw_ip = ip_entry.decode().split("|")
            ip = validate_ip(raw_ip)
            capture(f"Dequeued IP: {ip} (banned at {timestamp})")
        except (ValueError, UnicodeDecodeError) as exc:
            capture(f"Failed to parse Redis queue entry: {ip_entry!r} - {exc}", level="ERROR")
            continue

        process_ip(db, ip, exploit_index)

        scan_count += 1
        if scan_count % VPN_ROTATE_INTERVAL == 0:
            capture(f"Rotating VPN after {scan_count} scans...")
            rotate_vpn()


if __name__ == "__main__":
    sys.exit(main())
