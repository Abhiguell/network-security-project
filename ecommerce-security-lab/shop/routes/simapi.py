"""
shop/routes/simapi.py: the controlled simulation API used by the Cyber Lab.

Every endpoint:
  * requires a valid HMAC-signed request from the lab (see security/apiauth.py)
  * only READS synthetic records (is_synthetic = 1); real customers, orders and
    payments are never returned or modified
  * writes security events (source='simulation') and incidents so the store's
    admin dashboard reacts like a real monitoring system

Endpoints (all JSON, all under /api/sim):
  GET  /status                 health + current simulation state
  POST /spyware/collect        return synthetic customer records ("exposed data")
  GET  /ransomware/state       sandbox file status
  POST /ransomware/start       lock dummy files in the sandbox (simulated)
  POST /ransomware/reset       restore sandbox + integrity check
  POST /trojan/event           receive simulated trojan activity / beacons
  POST /reset                  reset all simulation effects
"""
import json
import random
import re

from flask import Blueprint, current_app, g, jsonify, request

from .. import ransomware_sandbox
from ..db import execute, get_setting, now_str, query
from ..security import monitor
from ..security.apiauth import require_lab_signature

bp = Blueprint("simapi", __name__, url_prefix="/api/sim")
BOT_RE = re.compile(r"^[A-Za-z0-9\-]{1,32}$")
FAKE_C2_COMMANDS = ["sleep 30", "noop", "report_status", "collect_sysinfo (simulated)", "sleep 60"]


def _operator():
    return f"lab:{g.lab_operator}"


def _event(severity, category, message, details=""):
    monitor.log_event(severity, category, message, details, username=_operator(), source="simulation")


def _open_incident(kind, severity, title, details):
    """One open incident per kind; repeated runs update it instead of piling up."""
    existing = query("SELECT id FROM incidents WHERE kind = ? AND status = 'open'", (kind,), one=True)
    if existing:
        execute("UPDATE incidents SET ts = ?, severity = ?, title = ?, details = ?, operator = ? WHERE id = ?",
                (now_str(), severity, title, details, _operator(), existing["id"]))
        return existing["id"]
    return execute("INSERT INTO incidents (ts, kind, severity, title, details, operator) VALUES (?, ?, ?, ?, ?, ?)",
                   (now_str(), kind, severity, title, details, _operator()))


def _traffic(module, kind, bot_id="", seq=0, nbytes=0, detail=""):
    execute("INSERT INTO sim_traffic (ts, ip, module, kind, bot_id, seq, bytes, operator, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now_str(), monitor.client_ip(), module, kind, bot_id, seq, nbytes, _operator(), detail[:200]))


@bp.route("/status")
@require_lab_signature
def status():
    sandbox = ransomware_sandbox.get_state(current_app.config["SANDBOX_FOLDER"])
    return jsonify({
        "ok": True, "store": current_app.config["APP_NAME"], "simulated": True, "server_time": now_str(),
        "sim_api_enabled": get_setting("sim_api_enabled", "1") == "1",
        "synthetic_records": query("SELECT COUNT(*) AS c FROM users WHERE is_synthetic = 1", one=True)["c"],
        "ransomware_active": sandbox["attacked"],
        "open_incidents": [dict(r) for r in query(
            "SELECT id, kind, severity, title, ts FROM incidents WHERE status = 'open' ORDER BY id DESC")],
        "security_status": monitor.security_status(),
    })


# ------------------------------------------------------------------ spyware
@bp.route("/spyware/collect", methods=["POST"])
@require_lab_signature
def spyware_collect():
    body = request.get_json(silent=True) or {}
    limit = max(1, min(int(body.get("limit", 25) or 25), 50))
    rows = query(
        "SELECT u.id, u.full_name, u.email, u.phone, u.address, u.city, "
        "  COUNT(o.id) AS orders, COALESCE(SUM(o.total), 0) AS spent, MAX(o.created_at) AS last_order "
        "FROM users u LEFT JOIN orders o ON o.user_id = u.id AND o.is_synthetic = 1 "
        "WHERE u.is_synthetic = 1 AND u.role = 'customer' "          # <- ONLY synthetic records
        "GROUP BY u.id ORDER BY u.id LIMIT ?", (limit,))
    records = [{
        "customer_id": f"SYN-{r['id']:04d}", "full_name": r["full_name"], "email": r["email"], "phone": r["phone"],
        "address": f"{r['address']}, {r['city']}", "orders": r["orders"], "total_spent": r["spent"],
        "last_order": r["last_order"], "password": "NOT EXPOSED (stored as salted hash)",
        "payment_data": "NOT STORED (handled by Midtrans)", "synthetic": True,
    } for r in rows]
    protected = query("SELECT COUNT(*) AS c FROM users WHERE is_synthetic = 0", one=True)["c"]
    size = len(json.dumps(records))
    _traffic("spyware", "data_access", nbytes=size, detail=f"{len(records)} synthetic records")
    _event("high", "Spyware Data Exposure",
           f"{len(records)} synthetic customer records read via simulation API (SIMULATED)",
           f"fields=name,email,phone,address,order_history bytes={size}")
    if len(records) >= 10:
        _event("critical", "Mass Data Access", f"Bulk read of {len(records)} customer profiles in one request",
               "indicator=unusual volume of PII access")
    incident = _open_incident("spyware", "high", f"Simulated spyware exposed {len(records)} synthetic customer records",
                              "Data categories: names, emails, phone numbers, addresses, order history")
    return jsonify({"simulated": True, "count": len(records), "records": records, "bytes": size,
                    "real_customers_protected": protected, "incident_id": incident,
                    "fields": ["customer_id", "full_name", "email", "phone", "address", "orders", "total_spent", "last_order"]})


# ------------------------------------------------------------------ ransomware
@bp.route("/ransomware/state")
@require_lab_signature
def ransomware_state():
    return jsonify(ransomware_sandbox.get_state(current_app.config["SANDBOX_FOLDER"]))


@bp.route("/ransomware/start", methods=["POST"])
@require_lab_signature
def ransomware_start():
    result = ransomware_sandbox.run_attack(current_app.config["SANDBOX_FOLDER"])
    n = len(result["files"])
    _traffic("ransomware", "file_lock", nbytes=sum(f["size"] for f in result["files"]), detail=f"{n} sandbox files")
    _event("high", "Ransomware Behavior", f"Mass file access: {n} store files opened in under 1 second (SIMULATED)",
           "folder=shop/sandbox/dummy_files")
    _event("critical", "Ransomware Behavior", f"{n} files renamed to *.locked + ransom note dropped (SIMULATED)",
           f"victim_id={result['state']['victim_id']}")
    result["incident_id"] = _open_incident(
        "ransomware", "critical", f"Simulated ransomware locked {n} files on the store server",
        f"Victim ID {result['state']['victim_id']} · ransom demand {result['state']['ransom']}")
    result["simulated"] = True
    return jsonify(result)


@bp.route("/ransomware/reset", methods=["POST"])
@require_lab_signature
def ransomware_reset():
    result = ransomware_sandbox.reset(current_app.config["SANDBOX_FOLDER"])
    execute("UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE kind = 'ransomware' AND status = 'open'",
            (now_str(),))
    _event("info", "Incident Response", "Ransomware sandbox restored from backup",
           f"integrity_ok={result['integrity_ok']}")
    result["simulated"] = True
    return jsonify(result)


# ------------------------------------------------------------------ trojan
@bp.route("/trojan/event", methods=["POST"])
@require_lab_signature
def trojan_event():
    body = request.get_json(silent=True) or {}
    phase = str(body.get("phase", ""))
    bot_id = str(body.get("bot_id", ""))
    bot_id = bot_id if BOT_RE.match(bot_id) else "unknown"
    seq = int(body.get("seq", 0) or 0)
    nbytes = int(body.get("bytes", 0) or 0)
    reply = {"simulated": True, "phase": phase}

    if phase == "install":
        _traffic("trojan", "install", bot_id, 0, nbytes, "FreeVoucherGenerator.exe (simulated)")
        _event("medium", "Suspicious Application",
               "Unknown app 'FreeVoucherGenerator.exe' launched on POS-TERMINAL-02 (SIMULATED)",
               f"bot_id={bot_id} signer=unsigned parent=browser_download")
        reply["incident_id"] = _open_incident("trojan", "high", "Simulated trojan activity on POS-TERMINAL-02",
                                              f"Bot {bot_id}: suspicious app + outbound C2 communication")
    elif phase == "beacon":
        _traffic("trojan", "beacon", bot_id, seq, nbytes, "periodic check-in")
        if seq == 1:
            _event("low", "Suspicious Connection", "POS-TERMINAL-02 opened a connection to an unknown host (SIMULATED)",
                   f"bot_id={bot_id}")
        reply["detected"] = monitor.analyze_beacon(bot_id, monitor.client_ip(), source="simulation",
                                                   label="trojan C2 server (simulated)")
        reply["cmd"] = random.choice(FAKE_C2_COMMANDS)
    elif phase == "exfil":
        _traffic("trojan", "exfil", bot_id, seq, nbytes, "system info upload (fake)")
        _event("high", "Trojan Data Upload", f"{nbytes} bytes of (fake) system info uploaded to C2 (SIMULATED)",
               f"bot_id={bot_id}")
    elif phase == "stop":
        _traffic("trojan", "stop", bot_id, seq, 0, "process terminated")
        _event("info", "Incident Response", "Trojan process terminated by analyst (SIMULATED)", f"bot_id={bot_id}")
    else:
        return jsonify({"error": "unknown phase"}), 400
    return jsonify(reply)


# ------------------------------------------------------------------ global reset
@bp.route("/reset", methods=["POST"])
@require_lab_signature
def reset_all():
    """Undo every simulation effect. Real customers, orders and payments are untouched."""
    sandbox = ransomware_sandbox.reset(current_app.config["SANDBOX_FOLDER"])
    resolved = query("SELECT COUNT(*) AS c FROM incidents WHERE status = 'open'", one=True)["c"]
    execute("UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE status = 'open'", (now_str(),))
    execute("UPDATE security_events SET acknowledged = 1 WHERE source = 'simulation'")
    execute("DELETE FROM sim_traffic")
    monitor._beacons.clear()
    monitor._beacon_alerted.clear()
    _event("info", "Simulation Reset", "Simulation environment reset by the Cyber Lab",
           f"incidents_resolved={resolved} sandbox_integrity_ok={sandbox['integrity_ok']}")
    return jsonify({"simulated": True, "incidents_resolved": resolved, "sandbox_integrity_ok": sandbox["integrity_ok"]})
