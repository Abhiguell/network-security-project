"""
lab/simulations.py: the three simulation modules.

Each run is stored in sim_runs, with step-by-step lines in run_logs, so the
web page can show a live execution log. All effects on the store happen ONLY
through the signed API in client.py.

  run_spyware()      -> reads SYNTHETIC customer records from the store
  run_ransomware()   -> locks dummy files in the store's sandbox (simulated)
  reset_ransomware() -> restores the sandbox and proves integrity
  start_trojan()     -> background thread: fake app + periodic C2 beacons
  stop_trojan()      -> asks the thread to stop
  reset_environment()-> undo every simulation effect on both sites
"""
import secrets
import threading
import time

import requests
from flask import current_app

from .client import ShopAPIError, ShopClient
from .db import add_event, add_log, finish_run, new_run, query

_trojan_stop = {}            # run_id -> threading.Event
_trojan_lock = threading.Lock()


def client_for(user):
    cfg = current_app.config
    return ShopClient(cfg["SHOP_URL"], cfg["SIM_API_SECRET"], cfg["SIM_API_CLIENT_ID"],
                      user["username"], user["role"],
                      http=current_app.extensions.get("shop_http", requests),   # tests plug in an adapter here
                      timeout=cfg["SHOP_TIMEOUT"])


# --------------------------------------------------------------------- spyware
def run_spyware(user, limit=25):
    op = user["username"]
    run_id = new_run("spyware", op)
    add_log(run_id, "info", "[SIMULATION] Spyware module started by " + op)
    add_log(run_id, "step", "Implant 'SyncHelper.dll' (simulated) loaded into the store's admin session")
    add_log(run_id, "step", f"Authenticating to LabMart simulation API ({current_app.config['SHOP_URL']}) with HMAC-SHA256")
    try:
        data = client_for(user).spyware_collect(limit)
    except ShopAPIError as exc:
        add_log(run_id, "error", f"Store refused the request: {exc}")
        add_event("medium", "spyware", f"Spyware simulation failed: {exc}", op)
        finish_run(run_id, "failed", {"error": str(exc)})
        return run_id
    n = data["count"]
    add_log(run_id, "step", "Querying customer table… (store only returns rows flagged is_synthetic = 1)")
    add_log(run_id, "warn", f"Harvested {n} SYNTHETIC customer records · {data['bytes']} bytes")
    add_log(run_id, "warn", "Fields exposed: " + ", ".join(data["fields"]))
    add_log(run_id, "ok", f"Passwords: NOT exposed (salted hashes) · Payment data: NOT stored (Midtrans) · "
                          f"{data['real_customers_protected']} real accounts protected")
    add_log(run_id, "alert", f"Store raised incident #{data['incident_id']} and HIGH/CRITICAL security events")
    add_log(run_id, "warn", "Follow-up attack: LabMart shoppers now see a fake 'verify your account' message "
                            "(phishing simulation, collects nothing)")
    add_event("high", "spyware", f"Simulated spyware accessed {n} synthetic customer records", op)
    finish_run(run_id, "completed", data, records=n)
    return run_id


# --------------------------------------------------------------------- ransomware
def run_ransomware(user):
    op = user["username"]
    run_id = new_run("ransomware", op)
    add_log(run_id, "info", "[SIMULATION] Ransomware module started by " + op)
    add_log(run_id, "step", "Payload 'invoice_update.exe' (simulated) executed on the store server")
    add_log(run_id, "step", "Target: shop/sandbox/dummy_files/ only. Real files are never touched")
    try:
        data = client_for(user).ransomware_start()
    except ShopAPIError as exc:
        add_log(run_id, "error", f"Store refused the request: {exc}")
        finish_run(run_id, "failed", {"error": str(exc)})
        return run_id
    for f in data["files"]:
        add_log(run_id, "warn", f"LOCKED  {f['name']}  →  {f['display_name']}")
    st = data["state"]
    add_log(run_id, "alert", f"Ransom note dropped · victim ID {st['victim_id']} · demand {st['ransom']}")
    add_log(run_id, "ok", "No file content changed (SHA-256 hashes recorded for the integrity check)")
    add_log(run_id, "alert", f"Store opened CRITICAL incident #{data['incident_id']}")
    add_event("critical", "ransomware", f"Simulated ransomware locked {len(data['files'])} sandbox files", op)
    finish_run(run_id, "completed", data, records=len(data["files"]))
    return run_id


def reset_ransomware(user):
    op = user["username"]
    run_id = new_run("ransomware", op)
    add_log(run_id, "info", "Incident response: restoring sandbox from 'backup'")
    try:
        data = client_for(user).ransomware_reset()
    except ShopAPIError as exc:
        add_log(run_id, "error", str(exc))
        finish_run(run_id, "failed", {"error": str(exc)})
        return run_id
    add_log(run_id, "ok" if data["integrity_ok"] else "error",
            "Integrity check: " + ("PASSED, every SHA-256 hash matches" if data["integrity_ok"] else "FAILED"))
    add_log(run_id, "ok", "Ransomware incident marked resolved in the store")
    add_event("info", "ransomware", "Ransomware sandbox restored", op)
    data["reset"] = True
    finish_run(run_id, "completed", data, records=len(data["files"]))
    return run_id


# --------------------------------------------------------------------- trojan
def trojan_running():
    return query("SELECT * FROM sim_runs WHERE module = 'trojan' AND status = 'running' ORDER BY id DESC", one=True)


def start_trojan(user, interval=2, count=12):
    if trojan_running():
        return None
    cfg = current_app.config
    interval = max(cfg["TROJAN_MIN_INTERVAL"], min(int(interval), 10))
    count = max(5, min(int(count), cfg["TROJAN_MAX_BEACONS"]))
    run_id = new_run("trojan", user["username"])
    stop = threading.Event()
    with _trojan_lock:
        _trojan_stop[run_id] = stop
    app = current_app._get_current_object()
    user_copy = {"username": user["username"], "role": user["role"]}
    t = threading.Thread(target=_trojan_worker, args=(app, run_id, user_copy, interval, count, stop), daemon=True)
    t.start()
    if app.config.get("TESTING"):
        t.join(timeout=30)                           # tests run the whole thing synchronously
    return run_id


def stop_trojan(run_id):
    with _trojan_lock:
        ev = _trojan_stop.get(run_id)
    if ev:
        ev.set()
        return True
    return False


def _trojan_worker(app, run_id, user, interval, count, stop):
    import json
    with app.app_context():
        op = user["username"]
        bot = "TRJ-" + secrets.token_hex(3).upper()
        client = client_for(user)
        traffic, status = [], "completed"

        def record(kind, seq, nbytes, reply):
            traffic.append({"ts": time.strftime("%H:%M:%S"), "kind": kind, "seq": seq, "bytes": nbytes,
                            "dest": app.config["SHOP_URL"] + "/api/sim/trojan/event",
                            "reply": reply.get("cmd", reply.get("phase", "")), "detected": bool(reply.get("detected"))})
            from .db import execute
            execute("UPDATE sim_runs SET result = ?, records = ? WHERE id = ?",
                    (json.dumps({"bot_id": bot, "traffic": traffic, "interval": interval}), len(traffic), run_id))

        try:
            add_log(run_id, "info", f"[SIMULATION] Trojan module started by {op} · bot id {bot}")
            add_log(run_id, "step", "User downloaded 'FreeVoucherGenerator.exe' from a fake promo site (simulated)")
            add_log(run_id, "step", "Fake app shows a voucher screen while a hidden routine starts (no file is written)")
            add_log(run_id, "info", "No persistence and no remote access are implemented. Network events only.")
            r = client.trojan_event("install", bot, 0, 0)
            record("install", 0, 0, r)
            add_log(run_id, "alert", f"Store flagged 'Suspicious Application' · incident #{r.get('incident_id')}")
            add_event("medium", "trojan", f"Trojan {bot} installed on POS-TERMINAL-02 (simulated)", op)
            detected_logged = False
            for seq in range(1, count + 1):
                if stop.wait(interval if seq > 1 else 0.3):
                    status = "stopped"
                    break
                size = 180 + secrets.randbelow(60)
                r = client.trojan_event("beacon", bot, seq, size)
                record("beacon", seq, size, r)
                add_log(run_id, "step", f"beacon #{seq} → C2 ({size} B) · reply: '{r.get('cmd')}'")
                if r.get("detected") and not detected_logged:
                    detected_logged = True
                    add_log(run_id, "alert", "Store IDS detected periodic C2 beaconing (low jitter) → HIGH alert")
                    add_event("high", "trojan", f"C2 beaconing from {bot} detected by store monitoring", op)
                if seq == 6:
                    r = client.trojan_event("exfil", bot, seq, 512)
                    record("exfil", seq, 512, r)
                    add_log(run_id, "warn", "Uploaded 512 B of FAKE system info (hostname, OS) to C2")
            r = client.trojan_event("stop", bot, len(traffic), 0)
            record("stop", len(traffic), 0, r)
            add_log(run_id, "ok" if status == "completed" else "warn",
                    "Trojan process terminated" + (" by analyst" if status == "stopped" else " (run finished)"))
            add_event("info", "trojan", f"Trojan {bot} simulation {status}", op)
        except ShopAPIError as exc:
            status = "failed"
            add_log(run_id, "error", f"Store refused the request: {exc}")
        except Exception as exc:                          # keep the lab alive whatever happens
            status = "failed"
            add_log(run_id, "error", f"Unexpected error: {exc.__class__.__name__}")
        finally:
            run = query("SELECT result, records FROM sim_runs WHERE id = ?", (run_id,), one=True)
            finish_run(run_id, status, json.loads(run["result"] or "{}"), run["records"])
            with _trojan_lock:
                _trojan_stop.pop(run_id, None)
            from .db import close_db
            close_db()


# --------------------------------------------------------------------- reset
def reset_environment(user):
    op = user["username"]
    run_id = new_run("reset", op)
    running = trojan_running()
    if running:
        stop_trojan(running["id"])
        add_log(run_id, "step", f"Stopping trojan run #{running['id']}")
    add_log(run_id, "info", "Resetting the simulation environment on the store…")
    try:
        data = client_for(user).reset_all()
    except ShopAPIError as exc:
        add_log(run_id, "error", str(exc))
        finish_run(run_id, "failed", {"error": str(exc)})
        return run_id
    add_log(run_id, "ok", f"Store: {data['incidents_resolved']} incident(s) resolved, simulation alerts acknowledged")
    add_log(run_id, "ok", "Sandbox integrity: " + ("PASSED" if data["sandbox_integrity_ok"] else "FAILED"))
    add_log(run_id, "ok", "Real customers, orders and payments were not modified")
    add_event("info", "reset", "Simulation environment reset", op)
    finish_run(run_id, "completed", data)
    return run_id
