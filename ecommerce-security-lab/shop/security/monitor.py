"""
app/security/monitor.py: the "security camera" of the website.

What it does:
  1. log_event()        -> records a security event (DB + logs/security.log)
  2. inspect_request()  -> scans every request for attack patterns
                           (SQL injection, XSS, path traversal, command injection,
                           hacking-tool user agents) and blocks them
  3. rate_limit_check() -> detects request floods (too many requests per minute)
  4. record_login()     -> tracks login attempts and detects brute force
  5. analyze_beacon()   -> detects malware "beaconing" (regular check-ins)
  6. log_activity()     -> writes every page visit to the activity log
  7. security_status()  -> SECURE / ELEVATED / UNDER ATTACK indicator
"""
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from statistics import mean, pstdev

from flask import abort, current_app, g, request

from ..db import TS_FORMAT, execute, now_str, query

SEVERITY_LEVELS = {"info": logging.INFO, "low": logging.INFO, "medium": logging.WARNING,
                   "high": logging.ERROR, "critical": logging.CRITICAL}

# ---------------------------------------------------------------------------
# Attack signatures. Each entry: (category, severity, regex)
# These are simplified versions of the rules used by Web Application Firewalls.
# ---------------------------------------------------------------------------
ATTACK_PATTERNS = [
    ("SQL Injection", "high", re.compile(
        r"(\bunion\b[\s\S]*\bselect\b|'\s*or\s+'?\d|'\s*or\s*'[^']*'\s*=\s*'|\bor\s+1\s*=\s*1\b"
        r"|;\s*drop\s+table|'\s*;\s*--|'\s*--|\bsleep\s*\(\s*\d|\binformation_schema\b)", re.I)),
    ("Cross-Site Scripting (XSS)", "high", re.compile(
        r"(<\s*script|javascript\s*:|on(error|load|mouseover|click)\s*=|<\s*iframe|<\s*svg[^>]*on\w+\s*=)", re.I)),
    ("Path Traversal", "high", re.compile(
        r"(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|/etc/passwd|\\windows\\win\.ini|boot\.ini)", re.I)),
    ("Command Injection", "high", re.compile(
        r"(;\s*(ls|cat|whoami|id|uname|wget|curl|nc|powershell)\b|\|\s*(nc|bash|sh|cmd)\b|`[^`]+`|\$\([^)]+\))", re.I)),
]

SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|acunetix|zgrab)", re.I)
OUTDATED_UA = re.compile(r"MSIE [2-6]\.", re.I)          # very old browsers are a common malware disguise

# Form fields we never scan or log (they may legitimately contain symbols)
SKIP_FIELDS = {"password", "current_password", "new_password", "confirm_password", "csrf_token"}

# Endpoints too noisy to put in the activity log
QUIET_ENDPOINTS = {"static", "admin.api_alerts", "admin.api_stats", "simapi.status", "simapi.ransomware_state"}

# In-memory counters (reset when the server restarts; fine for a lab)
_hits = defaultdict(deque)
_flood_alerted = {}
_beacons = defaultdict(deque)
_beacon_alerted = {}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def _file_logger():
    """Logger that appends to logs/security.log (one handler per log file)."""
    path = os.path.abspath(os.path.join(current_app.config["LOG_FOLDER"], "security.log"))
    logger = logging.getLogger("labmart.security")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(getattr(h, "baseFilename", None) == path for h in logger.handlers):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger


def client_ip():
    # We use the real socket address. X-Forwarded-For is NOT trusted because
    # an attacker can type any value into that header.
    return request.remote_addr or "unknown"


def log_event(severity, category, message, details="", ip=None, username=None, source="web"):
    """Save a security event to the database and to logs/security.log."""
    if username is None:
        user = g.get("user")
        username = user["username"] if user else None
    ip = ip or client_ip()
    execute(
        "INSERT INTO security_events (ts, severity, category, message, ip, username, details, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now_str(), severity, category, message[:300], ip, username, (details or "")[:1000], source),
    )
    _file_logger().log(SEVERITY_LEVELS.get(severity, logging.INFO),
                       f"[{source}] {category} | {message} | ip={ip} user={username} | {details}")


# ---------------------------------------------------------------------------
# Request inspection (a mini Web Application Firewall)
# ---------------------------------------------------------------------------
def _values_to_scan():
    yield "path", request.path
    for key, value in request.args.items(multi=True):
        yield f"query:{key}", value
    if request.method == "POST" and request.mimetype in ("application/x-www-form-urlencoded",
                                                         "multipart/form-data"):
        for key, value in request.form.items(multi=True):
            if key not in SKIP_FIELDS:
                yield f"form:{key}", value


def inspect_request():
    """Block requests that contain attack signatures."""
    ua = request.headers.get("User-Agent", "")
    if SCANNER_UA.search(ua):
        log_event("high", "Hacking Tool Detected", "Request from a known attack/scanner tool",
                  f"user_agent={ua[:200]} path={request.path}")
        abort(403, description="Automated attack tool detected. Request blocked.")
    if OUTDATED_UA.search(ua):
        log_event("medium", "Suspicious User-Agent", "Request with an outdated browser signature "
                  "(common malware disguise)", f"user_agent={ua[:200]} path={request.path}")

    for field, value in _values_to_scan():
        for category, severity, pattern in ATTACK_PATTERNS:
            if pattern.search(value or ""):
                log_event(severity, category, f"{category} attempt blocked in {field}",
                          f"path={request.path} payload={value[:200]!r}")
                abort(403, description=f"{category} attempt detected and blocked. "
                                       "This event has been reported to the administrator.")


def rate_limit_check():
    """Detect and block request floods (a simple anti-DoS / anti-bot measure)."""
    ip, t = client_ip(), time.time()
    hits = _hits[ip]
    hits.append(t)
    while hits and t - hits[0] > 60:
        hits.popleft()
    limit = current_app.config["RATE_LIMIT_PER_MINUTE"]
    if len(hits) > limit:
        if t - _flood_alerted.get(ip, 0) > 60:
            _flood_alerted[ip] = t
            log_event("medium", "Request Flood", f"{len(hits)} requests in 60 seconds (limit {limit})")
        abort(429)


# ---------------------------------------------------------------------------
# Login monitoring
# ---------------------------------------------------------------------------
def record_login(username, success):
    ip = client_ip()
    execute("INSERT INTO login_attempts (ts, username, ip, success) VALUES (?, ?, ?, ?)",
            (now_str(), (username or "")[:50], ip, 1 if success else 0))
    if success:
        return
    cfg = current_app.config
    since = (datetime.now() - timedelta(minutes=cfg["BRUTE_FORCE_WINDOW_MIN"])).strftime(TS_FORMAT)
    failures = query("SELECT COUNT(*) AS c FROM login_attempts WHERE ip = ? AND success = 0 AND ts >= ?",
                     (ip, since), one=True)["c"]
    threshold = cfg["BRUTE_FORCE_THRESHOLD"]
    if failures >= threshold and failures % threshold == 0:
        log_event("high", "Brute Force Attack",
                  f"{failures} failed logins from {ip} in {cfg['BRUTE_FORCE_WINDOW_MIN']} minutes",
                  f"last username tried={username[:50]!r}", username="")
    else:
        log_event("low", "Failed Login", f"Failed login for username '{username[:50]}'", username="")


# ---------------------------------------------------------------------------
# Malware beacon detection
# ---------------------------------------------------------------------------
def analyze_beacon(bot_id, ip, source="web", label="C2 endpoint"):
    """
    Malware usually "phones home" to its command-and-control (C2) server at a
    fixed interval. Human browsing is irregular; a bot is clockwork.
    We flag a host when 5+ check-ins arrive with very low timing variation (jitter).
    """
    key, t = (ip, bot_id), time.time()
    times = _beacons[key]
    times.append(t)
    while len(times) > 10:
        times.popleft()
    if len(times) < 5:
        return False
    stamps = list(times)
    intervals = [b - a for a, b in zip(stamps, stamps[1:])]
    avg, jitter = mean(intervals), pstdev(intervals)
    if avg < 120 and jitter <= max(1.0, avg * 0.2):
        if t - _beacon_alerted.get(key, 0) > 60:
            _beacon_alerted[key] = t
            log_event("high", "C2 Beaconing",
                      f"Host {ip} contacts the {label} every {avg:.1f}s (jitter {jitter:.2f}s)",
                      f"bot_id={bot_id} samples={len(stamps)}", ip=ip, username="", source=source)
        return True
    return False


# ---------------------------------------------------------------------------
# Activity log + status indicator
# ---------------------------------------------------------------------------
def log_activity(response):
    if request.endpoint in QUIET_ENDPOINTS or request.endpoint is None and request.path.startswith("/static"):
        return
    user = g.get("user")
    try:
        execute(
            "INSERT INTO activity_log (ts, user_id, username, ip, method, path, status, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now_str(), user["id"] if user else None, user["username"] if user else None,
             client_ip(), request.method, request.full_path.rstrip("?")[:300],
             response.status_code, request.headers.get("User-Agent", "")[:200]),
        )
    except Exception:          # logging must never break the website
        pass


def security_status():
    """Overall threat level, based on unacknowledged serious events in the last hour."""
    since = (datetime.now() - timedelta(hours=1)).strftime(TS_FORMAT)
    row = query(
        "SELECT SUM(severity = 'critical') AS crit, SUM(severity = 'high') AS high "
        "FROM security_events WHERE acknowledged = 0 AND ts >= ?", (since,), one=True)
    crit, high = row["crit"] or 0, row["high"] or 0
    if crit or high >= 5:
        return {"level": "danger", "label": "UNDER ATTACK", "crit": crit, "high": high}
    if high:
        return {"level": "warning", "label": "ELEVATED", "crit": crit, "high": high}
    return {"level": "ok", "label": "SECURE", "crit": crit, "high": high}
