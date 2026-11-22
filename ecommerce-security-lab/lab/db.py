"""
lab/db.py: the Cyber Lab's own SQLite database (separate from the store's).

Tables:
  lab_users   lab operators with roles admin / analyst / viewer
  sim_runs    one row per simulation run (status + JSON results)
  run_logs    execution log lines for each run
  lab_events  the lab's own security event log
"""
import json
import sqlite3
from datetime import datetime

from flask import current_app, g
from werkzeug.security import generate_password_hash

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,                 -- admin | analyst | viewer
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS sim_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL,               -- spyware | ransomware | trojan | reset
    status TEXT NOT NULL,               -- running | completed | stopped | failed
    operator TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    records INTEGER DEFAULT 0,
    result TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS run_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES sim_runs(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,                -- info | step | warn | alert | ok | error
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lab_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    module TEXT NOT NULL,
    message TEXT NOT NULL,
    operator TEXT
);
"""


def now_str():
    return datetime.now().strftime(TS_FORMAT)


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    rows = get_db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


# ---------- helpers used by the simulations (also from background threads) ----------
def add_log(run_id, level, message):
    execute("INSERT INTO run_logs (run_id, ts, level, message) VALUES (?, ?, ?, ?)",
            (run_id, now_str(), level, message[:400]))


def add_event(severity, module, message, operator=None):
    execute("INSERT INTO lab_events (ts, severity, module, message, operator) VALUES (?, ?, ?, ?, ?)",
            (now_str(), severity, module, message[:300], operator))


def new_run(module, operator):
    return execute("INSERT INTO sim_runs (module, status, operator, started_at) VALUES (?, 'running', ?, ?)",
                   (module, operator, now_str()))


def finish_run(run_id, status, result=None, records=0):
    execute("UPDATE sim_runs SET status = ?, ended_at = ?, result = ?, records = ? WHERE id = ?",
            (status, now_str(), json.dumps(result or {}), records, run_id))


def run_as_dict(run_id, after_log_id=0):
    run = query("SELECT * FROM sim_runs WHERE id = ?", (run_id,), one=True)
    if run is None:
        return None
    logs = query("SELECT id, ts, level, message FROM run_logs WHERE run_id = ? AND id > ? ORDER BY id",
                 (run_id, after_log_id))
    data = dict(run)
    data["result"] = json.loads(run["result"] or "{}")
    data["logs"] = [dict(r) for r in logs]
    return data


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(SCHEMA)
        for username, password, role in app.config["DEFAULT_USERS"]:
            if query("SELECT id FROM lab_users WHERE username = ?", (username,), one=True) is None:
                execute("INSERT INTO lab_users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                        (username, generate_password_hash(password), role, now_str()))
        # Runs that were 'running' when the server stopped can't still be running.
        execute("UPDATE sim_runs SET status = 'stopped', ended_at = ? WHERE status = 'running'", (now_str(),))
