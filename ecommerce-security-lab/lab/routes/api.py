"""
lab/routes/api.py: JSON endpoints used by the lab's own pages.

Every endpoint requires a signed-in lab operator (+ CSRF token on POST).
Starting / stopping / resetting requires role admin or analyst.
"""
from flask import Blueprint, g, jsonify, request

from .. import simulations as sim
from ..client import ShopAPIError
from ..db import run_as_dict
from ..security.access import RUN_ROLES, login_required, roles_required

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/status")
@login_required
def status():
    """Is the store reachable, and what is its current state?"""
    try:
        shop = sim.client_for(g.user).status()
        return jsonify({"online": True, "shop": shop, "trojan_running": bool(sim.trojan_running())})
    except ShopAPIError as exc:
        return jsonify({"online": False, "error": exc.message, "code": exc.status,
                        "trojan_running": bool(sim.trojan_running())})


@bp.route("/runs/<int:run_id>")
@login_required
def run(run_id):
    data = run_as_dict(run_id, request.args.get("after", 0, type=int))
    return (jsonify(data), 200) if data else (jsonify({"error": "not found"}), 404)


@bp.route("/spyware/start", methods=["POST"])
@login_required
@roles_required(*RUN_ROLES)
def spyware_start():
    return jsonify({"run_id": sim.run_spyware(g.user)})


@bp.route("/ransomware/start", methods=["POST"])
@login_required
@roles_required(*RUN_ROLES)
def ransomware_start():
    return jsonify({"run_id": sim.run_ransomware(g.user)})


@bp.route("/ransomware/state")
@login_required
def ransomware_state():
    try:
        return jsonify(sim.client_for(g.user).ransomware_state())
    except ShopAPIError as exc:
        return jsonify({"error": exc.message}), 502


@bp.route("/ransomware/reset", methods=["POST"])
@login_required
@roles_required(*RUN_ROLES)
def ransomware_reset():
    return jsonify({"run_id": sim.reset_ransomware(g.user)})


@bp.route("/trojan/start", methods=["POST"])
@login_required
@roles_required(*RUN_ROLES)
def trojan_start():
    body = request.get_json(silent=True) or {}
    run_id = sim.start_trojan(g.user, body.get("interval", 2), body.get("count", 12))
    if run_id is None:
        return jsonify({"error": "busy", "message": "A trojan simulation is already running."}), 409
    return jsonify({"run_id": run_id})


@bp.route("/trojan/stop", methods=["POST"])
@login_required
@roles_required(*RUN_ROLES)
def trojan_stop():
    running = sim.trojan_running()
    if not running:
        return jsonify({"stopped": False, "message": "No trojan simulation is running."})
    return jsonify({"stopped": sim.stop_trojan(running["id"]), "run_id": running["id"]})


@bp.route("/reset", methods=["POST"])
@login_required
@roles_required("admin", "analyst")
def reset():
    return jsonify({"run_id": sim.reset_environment(g.user)})
