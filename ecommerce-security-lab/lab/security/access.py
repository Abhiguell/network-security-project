"""
lab/security/access.py: lab login sessions, CSRF and role-based authorisation.

Roles:
  admin    run every simulation + reset the whole environment
  analyst  run simulations
  viewer   read-only (can watch, cannot start anything)
"""
import hashlib
import hmac
import secrets
from functools import wraps

from flask import abort, flash, g, jsonify, redirect, request, session, url_for

from ..db import add_event, query

RUN_ROLES = ("admin", "analyst")


def _fp():
    return hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()


def login_user(user):
    session.clear()
    session.permanent = True
    session["lab_uid"] = user["id"]
    session["fp"] = _fp()


def load_user():
    g.user = None
    uid = session.get("lab_uid")
    if uid is None:
        return
    if session.get("fp") != _fp():
        add_event("high", "auth", "Lab session reused from a different browser. Session terminated.")
        session.clear()
        return
    g.user = query("SELECT * FROM lab_users WHERE id = ?", (uid,), one=True)


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def csrf_protect():
    if request.method != "POST":
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    if not hmac.compare_digest(sent, session.get("_csrf", "") or "x"):
        add_event("medium", "auth", f"POST without valid CSRF token: {request.path}")
        abort(400, description="Invalid or missing security token. Reload the page.")


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "login required"}), 401
            flash("Please sign in to the lab.", "warning")
            return redirect(url_for("auth.login"))
        return view(*a, **kw)
    return wrapped


def roles_required(*roles):
    """Authorisation check: only the listed roles may call this endpoint."""
    def deco(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if g.user is None:
                return jsonify({"error": "login required"}), 401
            if g.user["role"] not in roles:
                add_event("medium", "auth", f"Role '{g.user['role']}' tried to call {request.path}", g.user["username"])
                return jsonify({"error": "forbidden",
                                "message": f"Your role '{g.user['role']}' is not allowed to do this."}), 403
            return view(*a, **kw)
        return wrapped
    return deco
