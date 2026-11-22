"""lab/routes/pages.py: HTML pages of the Cyber Lab."""
from flask import Blueprint, abort, render_template

from ..db import query
from ..security.access import login_required

bp = Blueprint("pages", __name__)

MODULES = {
    "spyware": {"title": "Spyware Simulation", "icon": "👁", "button": "Start Spyware Simulation", "color": "warning",
                "summary": "Covertly harvests customer records from the store and shows what an attacker would see."},
    "ransomware": {"title": "Ransomware Simulation", "icon": "🔒", "button": "Start Ransomware Simulation", "color": "danger",
                   "summary": "Locks dummy files in the store's sandbox folder and raises a critical incident."},
    "trojan": {"title": "Trojan Simulation", "icon": "🐴", "button": "Start Trojan Simulation", "color": "blue",
               "summary": "A fake 'voucher generator' app hides a routine that beacons to a C2 server."},
}


@bp.route("/")
@login_required
def dashboard():
    last = {m: query("SELECT * FROM sim_runs WHERE module = ? ORDER BY id DESC LIMIT 1", (m,), one=True) for m in MODULES}
    counts = {m: query("SELECT COUNT(*) AS c FROM sim_runs WHERE module = ?", (m,), one=True)["c"] for m in MODULES}
    events = query("SELECT * FROM lab_events ORDER BY id DESC LIMIT 12")
    return render_template("dashboard.html", modules=MODULES, last=last, counts=counts, events=events)


@bp.route("/module/<name>")
@login_required
def module(name):
    if name not in MODULES:
        abort(404)
    history = query("SELECT * FROM sim_runs WHERE module = ? ORDER BY id DESC LIMIT 8", (name,))
    return render_template(f"modules/{name}.html", name=name, m=MODULES[name], history=history)


@bp.route("/events")
@login_required
def events():
    rows = query("SELECT * FROM lab_events ORDER BY id DESC LIMIT 300")
    runs = query("SELECT * FROM sim_runs ORDER BY id DESC LIMIT 50")
    return render_template("events.html", events=rows, runs=runs)
